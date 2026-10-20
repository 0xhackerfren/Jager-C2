package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
)

const (
	counterSize        = 4
	nonceSize          = 12
	tagSize            = 16
	headerSize         = counterSize + nonceSize + tagSize
	sessionKeyLen      = 32
	p256KeySize        = 32
	SessionIDHashSize  = 16
	MaxCounterGap      = 1000

	bcryptECDSAPublicP256Magic = 0x31534345 // "ECS1"
)

var (
	ErrNotInitialized   = errors.New("session crypto not initialized")
	ErrReplay           = errors.New("replay detected: counter not monotonic")
	ErrCounterJump      = errors.New("suspicious counter jump")
	ErrInvalidPacket    = errors.New("invalid encrypted packet")
	ErrInvalidPublicKey = errors.New("invalid ECDH public key")
)

// SessionCrypto holds per-session ECDH + AES-GCM state.
type SessionCrypto struct {
	mu             sync.Mutex
	SessionKey     []byte // 32-byte AES key derived from ECDH
	SessionIDHash  [SessionIDHashSize]byte
	SendCounter    uint32
	RecvCounter    uint32
	SendNonce      [12]byte // Template nonce (counter fills first 4 bytes)
	RecvNonce      [12]byte
	Initialized    bool
	HasSessionID   bool
	PrivKey        *ecdh.PrivateKey // Server ephemeral key for this session
}

// Ready reports whether ECDH key exchange completed and wire crypto is active.
func (sc *SessionCrypto) Ready() bool {
	if sc == nil {
		return false
	}
	sc.mu.Lock()
	defer sc.mu.Unlock()
	return sc.Initialized && len(sc.SessionKey) > 0
}

// Invalidate clears derived keys so stale crypto cannot be used after re-registration.
func (sc *SessionCrypto) Invalidate() {
	if sc == nil {
		return
	}
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.SessionKey = nil
	sc.Initialized = false
}

// ComputeSessionIDHash returns the first 16 bytes of SHA256(sessionID).
func ComputeSessionIDHash(sessionID string) [SessionIDHashSize]byte {
	sum := sha256.Sum256([]byte(sessionID))
	var out [SessionIDHashSize]byte
	copy(out[:], sum[:SessionIDHashSize])
	return out
}

// SetSessionID stores the truncated hash used as the wire routing prefix.
func (sc *SessionCrypto) SetSessionID(sessionID string) {
	if sc == nil || sessionID == "" {
		return
	}
	sc.SessionIDHash = ComputeSessionIDHash(sessionID)
	sc.HasSessionID = true
}

// HeaderSize returns the AES-GCM wire header length (counter + nonce + tag).
func HeaderSize() int { return headerSize }

// GenerateKeyPair creates a new ECDH P-256 keypair for a session registration.
// Returns SessionCrypto state and the server public key as a BCRYPT_ECCPUBLIC_BLOB.
func GenerateKeyPair() (*SessionCrypto, []byte, error) {
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate ecdh key: %w", err)
	}

	sc := &SessionCrypto{
		PrivKey:     priv,
		Initialized: false,
	}

	if _, err := rand.Read(sc.SendNonce[counterSize:]); err != nil {
		return nil, nil, fmt.Errorf("generate send nonce: %w", err)
	}
	if _, err := rand.Read(sc.RecvNonce[counterSize:]); err != nil {
		return nil, nil, fmt.Errorf("generate recv nonce: %w", err)
	}

	pubBlob, err := ecdhPublicToBcryptBlob(priv.PublicKey().Bytes())
	if err != nil {
		return nil, nil, err
	}

	return sc, pubBlob, nil
}

// DeriveSessionKey completes ECDH with the client's public key (BCRYPT_ECCPUBLIC_BLOB).
func (sc *SessionCrypto) DeriveSessionKey(clientPubKeyBytes []byte) error {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	if sc == nil || sc.PrivKey == nil {
		return ErrNotInitialized
	}

	goPub, err := bcryptPublicBlobToECDH(clientPubKeyBytes)
	if err != nil {
		return err
	}

	clientPub, err := ecdh.P256().NewPublicKey(goPub)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidPublicKey, err)
	}

	shared, err := sc.PrivKey.ECDH(clientPub)
	if err != nil {
		return fmt.Errorf("ecdh agreement: %w", err)
	}

	// Match Windows BCryptDeriveKey(BCRYPT_KDF_HASH, SHA256).
	sum := sha256.Sum256(shared)
	sc.SessionKey = sum[:]
	sc.Initialized = true
	sc.PrivKey = nil // Ephemeral private key no longer needed after derivation.
	return nil
}

// Encrypt a plaintext message.
// Returns: [16B session_id_hash][4B counter_be][12B nonce][16B tag][ciphertext]
func (sc *SessionCrypto) Encrypt(plaintext []byte) ([]byte, error) {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	if sc == nil || !sc.Initialized {
		return nil, ErrNotInitialized
	}

	sc.SendCounter++
	counter := sc.SendCounter

	nonce := sc.SendNonce
	binary.BigEndian.PutUint32(nonce[0:counterSize], counter)

	block, err := aes.NewCipher(sc.SessionKey)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}

	sealed := gcm.Seal(nil, nonce[:], plaintext, nil)
	if len(sealed) < tagSize {
		return nil, ErrInvalidPacket
	}

	ctLen := len(sealed) - tagSize
	ciphertext := sealed[:ctLen]
	tag := sealed[ctLen:]

	prefixLen := 0
	if sc.HasSessionID {
		prefixLen = SessionIDHashSize
	}

	packet := make([]byte, prefixLen+headerSize+ctLen)
	off := 0
	if sc.HasSessionID {
		copy(packet[:SessionIDHashSize], sc.SessionIDHash[:])
		off = SessionIDHashSize
	}

	binary.BigEndian.PutUint32(packet[off:off+counterSize], counter)
	copy(packet[off+counterSize:off+counterSize+nonceSize], nonce[:])
	copy(packet[off+counterSize+nonceSize:off+headerSize], tag)
	copy(packet[off+headerSize:], ciphertext)
	return packet, nil
}

// Decrypt a message.
// Expects: [16B session_id_hash][4B counter_be][12B nonce][16B tag][ciphertext]
// Legacy packets without the prefix are still accepted when HasSessionID is false.
func (sc *SessionCrypto) Decrypt(packet []byte) ([]byte, error) {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	if sc == nil || !sc.Initialized {
		return nil, ErrNotInitialized
	}

	off := 0
	if sc.HasSessionID && len(packet) > SessionIDHashSize+headerSize {
		if !bytes.Equal(packet[:SessionIDHashSize], sc.SessionIDHash[:]) {
			return nil, ErrInvalidPacket
		}
		off = SessionIDHashSize
	}

	cryptoPacket := packet[off:]
	if len(cryptoPacket) <= headerSize {
		return nil, ErrInvalidPacket
	}

	counter := binary.BigEndian.Uint32(cryptoPacket[0:counterSize])
	if counter <= sc.RecvCounter {
		return nil, ErrReplay
	}
	if counter > sc.RecvCounter+MaxCounterGap {
		return nil, ErrCounterJump
	}

	nonce := cryptoPacket[counterSize : counterSize+nonceSize]
	tag := cryptoPacket[counterSize+nonceSize : headerSize]
	ciphertext := cryptoPacket[headerSize:]

	block, err := aes.NewCipher(sc.SessionKey)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}

	combined := append(append([]byte(nil), ciphertext...), tag...)
	plaintext, err := gcm.Open(nil, nonce, combined, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	sc.RecvCounter = counter
	copy(sc.RecvNonce[:], nonce)
	return plaintext, nil
}

func ecdhPublicToBcryptBlob(pub []byte) ([]byte, error) {
	var x, y []byte
	switch len(pub) {
	case 1 + 2*p256KeySize:
		if pub[0] != 0x04 {
			return nil, ErrInvalidPublicKey
		}
		x = pub[1 : 1+p256KeySize]
		y = pub[1+p256KeySize:]
	default:
		return nil, fmt.Errorf("%w: unsupported length %d", ErrInvalidPublicKey, len(pub))
	}

	blob := make([]byte, 8+2*p256KeySize)
	binary.LittleEndian.PutUint32(blob[0:4], bcryptECDSAPublicP256Magic)
	binary.LittleEndian.PutUint32(blob[4:8], p256KeySize)
	copy(blob[8:], x)
	copy(blob[8+p256KeySize:], y)
	return blob, nil
}

func bcryptPublicBlobToECDH(blob []byte) ([]byte, error) {
	if len(blob) != 8+2*p256KeySize {
		return nil, fmt.Errorf("%w: invalid blob length %d", ErrInvalidPublicKey, len(blob))
	}

	magic := binary.LittleEndian.Uint32(blob[0:4])
	if magic != bcryptECDSAPublicP256Magic {
		return nil, fmt.Errorf("%w: invalid magic 0x%x", ErrInvalidPublicKey, magic)
	}

	cbKey := binary.LittleEndian.Uint32(blob[4:8])
	if cbKey != p256KeySize {
		return nil, fmt.Errorf("%w: invalid key size %d", ErrInvalidPublicKey, cbKey)
	}

	x := blob[8 : 8+p256KeySize]
	y := blob[8+p256KeySize : 8+2*p256KeySize]

	out := make([]byte, 1+2*p256KeySize)
	out[0] = 0x04
	copy(out[1:], x)
	copy(out[1+p256KeySize:], y)
	return out, nil
}
