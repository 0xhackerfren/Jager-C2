package crypto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"sync"
	"testing"
)

func derivePair(t *testing.T) (*SessionCrypto, *SessionCrypto) {
	t.Helper()

	serverSC, serverPub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("server GenerateKeyPair: %v", err)
	}

	clientSC, clientPub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("client GenerateKeyPair: %v", err)
	}

	if err := serverSC.DeriveSessionKey(clientPub); err != nil {
		t.Fatalf("server DeriveSessionKey: %v", err)
	}
	if err := clientSC.DeriveSessionKey(serverPub); err != nil {
		t.Fatalf("client DeriveSessionKey: %v", err)
	}

	if !bytes.Equal(serverSC.SessionKey, clientSC.SessionKey) {
		t.Fatal("derived session keys do not match")
	}

	return serverSC, clientSC
}

func TestKeyExchange(t *testing.T) {
	derivePair(t)
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	sender, receiver := derivePair(t)

	plaintext := []byte("jager round-trip payload")
	packet, err := sender.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	got, err := receiver.Decrypt(packet)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(plaintext, got) {
		t.Fatalf("plaintext mismatch: got %q want %q", got, plaintext)
	}
}

func TestReplayRejection(t *testing.T) {
	sender, receiver := derivePair(t)

	msg1, err := sender.Encrypt([]byte("first"))
	if err != nil {
		t.Fatalf("encrypt msg1: %v", err)
	}
	msg2, err := sender.Encrypt([]byte("second"))
	if err != nil {
		t.Fatalf("encrypt msg2: %v", err)
	}

	if _, err := receiver.Decrypt(msg1); err != nil {
		t.Fatalf("decrypt msg1: %v", err)
	}
	if _, err := receiver.Decrypt(msg2); err != nil {
		t.Fatalf("decrypt msg2: %v", err)
	}

	_, err = receiver.Decrypt(msg1)
	if !errors.Is(err, ErrReplay) {
		t.Fatalf("expected ErrReplay, got %v", err)
	}
}

func TestDecryptInvalidTag(t *testing.T) {
	sender, receiver := derivePair(t)

	packet, err := sender.Encrypt([]byte("tamper me"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Corrupt authentication tag (bytes 16:32 in header).
	packet[counterSize+nonceSize] ^= 0xFF

	_, err = receiver.Decrypt(packet)
	if err == nil {
		t.Fatal("expected decrypt failure for corrupted tag")
	}
}

func TestReadyAndInvalidate(t *testing.T) {
	sc, serverPub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	if sc.Ready() {
		t.Fatal("expected crypto not ready before ECDH")
	}

	_, clientPub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("client GenerateKeyPair: %v", err)
	}
	if err := sc.DeriveSessionKey(clientPub); err != nil {
		t.Fatalf("DeriveSessionKey: %v", err)
	}
	_ = serverPub
	if !sc.Ready() {
		t.Fatal("expected crypto ready after ECDH")
	}

	sc.Invalidate()
	if sc.Ready() {
		t.Fatal("expected crypto not ready after Invalidate")
	}

	_, err = sc.Encrypt([]byte("test"))
	if !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("expected ErrNotInitialized after Invalidate, got %v", err)
	}
}

func TestConcurrentEncryptMutex(t *testing.T) {
	sender, receiver := derivePair(t)
	sender.SetSessionID("concurrent-session")
	receiver.SetSessionID("concurrent-session")

	const goroutines = 32
	packets := make([][]byte, goroutines)
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		i := i
		go func() {
			defer wg.Done()
			msg := []byte(fmt.Sprintf("msg-%d", i))
			pkt, err := sender.Encrypt(msg)
			if err != nil {
				t.Errorf("encrypt msg-%d: %v", i, err)
				return
			}
			packets[i] = pkt
		}()
	}
	wg.Wait()

	prefix := SessionIDHashSize
	sort.Slice(packets, func(i, j int) bool {
		offI := 0
		offJ := 0
		if sender.HasSessionID {
			offI = prefix
			offJ = prefix
		}
		return binary.BigEndian.Uint32(packets[i][offI:offI+counterSize]) <
			binary.BigEndian.Uint32(packets[j][offJ:offJ+counterSize])
	})

	for i, pkt := range packets {
		if pkt == nil {
			t.Fatalf("missing packet at index %d", i)
		}
		_, err := receiver.Decrypt(pkt)
		if err != nil {
			t.Fatalf("decrypt packet %d: %v", i, err)
		}
	}
}

func TestSessionIDHashSize(t *testing.T) {
	if SessionIDHashSize != 16 {
		t.Fatalf("SessionIDHashSize = %d, want 16", SessionIDHashSize)
	}
	hash := ComputeSessionIDHash("test-session")
	if len(hash) != 16 {
		t.Fatalf("hash length = %d, want 16", len(hash))
	}
}

func TestDecryptShortPacket(t *testing.T) {
	sc := &SessionCrypto{
		SessionKey:  bytes.Repeat([]byte{0xAB}, sessionKeyLen),
		Initialized: true,
	}

	shortPackets := [][]byte{
		nil,
		{},
		make([]byte, headerSize-1),
		make([]byte, headerSize),
	}

	for i, pkt := range shortPackets {
		_, err := sc.Decrypt(pkt)
		if err == nil {
			t.Fatalf("packet %d: expected error for short/empty packet", i)
		}
		if !errors.Is(err, ErrInvalidPacket) && len(pkt) <= headerSize {
			t.Fatalf("packet %d: expected ErrInvalidPacket, got %v", i, err)
		}
	}
}
