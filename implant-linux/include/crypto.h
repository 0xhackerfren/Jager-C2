#ifndef JAGER_LINUX_CRYPTO_H
#define JAGER_LINUX_CRYPTO_H

#include "config.h"

#define SESSION_ID_HASH_SIZE 16
#define MAX_COUNTER_GAP      1000

typedef struct {
    BYTE session_key[32];
    BYTE send_nonce[12];
    BYTE recv_nonce[12];
    BYTE session_id_hash[SESSION_ID_HASH_SIZE];
    DWORD send_counter;
    DWORD recv_counter;
    BOOL initialized;
    BOOL has_session_id;
} CRYPTO_CTX;

BOOL crypto_init(CRYPTO_CTX *ctx, BYTE *pubkey_out, DWORD *pubkey_len);
BOOL crypto_derive_session_key(CRYPTO_CTX *ctx, const BYTE *server_pubkey, DWORD server_pubkey_len);
void crypto_set_session_id(CRYPTO_CTX *ctx, const char *session_id);
BYTE *crypto_encrypt(CRYPTO_CTX *ctx, const BYTE *plaintext, DWORD pt_len, DWORD *out_len);
BYTE *crypto_decrypt(CRYPTO_CTX *ctx, const BYTE *packet, DWORD pkt_len, DWORD *out_len);
void crypto_cleanup(CRYPTO_CTX *ctx);

#endif
