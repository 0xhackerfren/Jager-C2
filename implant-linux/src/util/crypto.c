/**
 * Linux crypto - ECDH P-256 + AES-256-GCM
 * Compatible with OpenSSL 1.1.x AND 3.x
 * Wire format matches Windows BCRYPT_ECCPUBLIC_BLOB + session crypto.
 */
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include "../../include/crypto.h"

#define CRYPTO_COUNTER_SIZE  4
#define CRYPTO_NONCE_SIZE    12
#define CRYPTO_TAG_SIZE      16
#define CRYPTO_HEADER_SIZE   (CRYPTO_COUNTER_SIZE + CRYPTO_NONCE_SIZE + CRYPTO_TAG_SIZE)
#define CRYPTO_SESSION_KEY   32
#define P256_KEY_SIZE        32
#define BCRYPT_P256_MAGIC    0x31534345  /* ECS1 */

static EC_KEY *g_ecdh_key = NULL;

static void secure_zero(BYTE *buf, DWORD len) {
    if (buf && len) {
        volatile BYTE *p = (volatile BYTE *)buf;
        while (len--) *p++ = 0;
    }
}

static void store_be32(BYTE *p, DWORD v) {
    p[0] = (BYTE)((v >> 24) & 0xFF);
    p[1] = (BYTE)((v >> 16) & 0xFF);
    p[2] = (BYTE)((v >> 8) & 0xFF);
    p[3] = (BYTE)(v & 0xFF);
}

static DWORD load_be32(const BYTE *p) {
    return ((DWORD)p[0] << 24) | ((DWORD)p[1] << 16) |
           ((DWORD)p[2] << 8) | (DWORD)p[3];
}

static BOOL sha256_trunc8(const char *session_id, BYTE out[SESSION_ID_HASH_SIZE]) {
    unsigned char hash[SHA256_DIGEST_LENGTH];

    if (!session_id || !session_id[0] || !out)
        return FALSE;

    SHA256((const unsigned char *)session_id, strlen(session_id), hash);
    memcpy(out, hash, SESSION_ID_HASH_SIZE);
    return TRUE;
}

void crypto_set_session_id(CRYPTO_CTX *ctx, const char *session_id) {
    if (!ctx || !session_id)
        return;
    if (sha256_trunc8(session_id, ctx->session_id_hash))
        ctx->has_session_id = TRUE;
}

static EC_KEY *ecdh_keygen(void) {
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!key) return NULL;

    if (EC_KEY_generate_key(key) != 1) {
        EC_KEY_free(key);
        return NULL;
    }
    return key;
}

static BOOL ec_pubkey_to_bcrypt_blob(EC_KEY *key, BYTE *out, DWORD *out_len) {
    const EC_POINT *pub = EC_KEY_get0_public_key(key);
    const EC_GROUP *group = EC_KEY_get0_group(key);
    if (!pub || !group) return FALSE;

    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    if (!x || !y) {
        BN_free(x);
        BN_free(y);
        return FALSE;
    }

    if (EC_POINT_get_affine_coordinates_GFp(group, pub, x, y, NULL) != 1) {
        BN_free(x);
        BN_free(y);
        return FALSE;
    }

    DWORD need = 8 + 2 * P256_KEY_SIZE;
    if (*out_len < need) {
        BN_free(x);
        BN_free(y);
        return FALSE;
    }

    out[0] = (BYTE)(BCRYPT_P256_MAGIC & 0xFF);
    out[1] = (BYTE)((BCRYPT_P256_MAGIC >> 8) & 0xFF);
    out[2] = (BYTE)((BCRYPT_P256_MAGIC >> 16) & 0xFF);
    out[3] = (BYTE)((BCRYPT_P256_MAGIC >> 24) & 0xFF);
    out[4] = P256_KEY_SIZE;
    out[5] = 0;
    out[6] = 0;
    out[7] = 0;

    memset(out + 8, 0, 2 * P256_KEY_SIZE);
    BN_bn2binpad(x, out + 8, P256_KEY_SIZE);
    BN_bn2binpad(y, out + 8 + P256_KEY_SIZE, P256_KEY_SIZE);

    BN_free(x);
    BN_free(y);
    *out_len = need;
    return TRUE;
}

static EC_KEY *ec_pubkey_from_bcrypt_blob(const BYTE *blob, DWORD blob_len) {
    if (blob_len != 8 + 2 * P256_KEY_SIZE) return NULL;

    DWORD magic = (DWORD)blob[0] | ((DWORD)blob[1] << 8) |
                  ((DWORD)blob[2] << 16) | ((DWORD)blob[3] << 24);
    if (magic != BCRYPT_P256_MAGIC) return NULL;
    if (blob[4] != P256_KEY_SIZE) return NULL;

    EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!key) return NULL;

    BIGNUM *x = BN_bin2bn(blob + 8, P256_KEY_SIZE, NULL);
    BIGNUM *y = BN_bin2bn(blob + 8 + P256_KEY_SIZE, P256_KEY_SIZE, NULL);
    if (!x || !y) {
        BN_free(x);
        BN_free(y);
        EC_KEY_free(key);
        return NULL;
    }

    if (EC_KEY_set_public_key_affine_coordinates(key, x, y) != 1) {
        BN_free(x);
        BN_free(y);
        EC_KEY_free(key);
        return NULL;
    }

    BN_free(x);
    BN_free(y);
    return key;
}

static BOOL aes_gcm_encrypt(const BYTE *key, const BYTE *nonce, DWORD nonce_len,
                            const BYTE *pt, DWORD pt_len, BYTE *ct, DWORD *ct_len,
                            BYTE *tag, DWORD tag_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return FALSE;

    int out_len = 0, final_len = 0;
    BOOL ok = FALSE;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto done;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto done;
    if (EVP_EncryptUpdate(ctx, ct, &out_len, pt, (int)pt_len) != 1) goto done;
    if (EVP_EncryptFinal_ex(ctx, ct + out_len, &final_len) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, (int)tag_len, tag) != 1) goto done;

    *ct_len = (DWORD)(out_len + final_len);
    ok = TRUE;

done:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

static BOOL aes_gcm_decrypt(const BYTE *key, const BYTE *nonce, DWORD nonce_len,
                            const BYTE *ct, DWORD ct_len, const BYTE *tag, DWORD tag_len,
                            BYTE *pt, DWORD *pt_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return FALSE;

    int out_len = 0, final_len = 0;
    BOOL ok = FALSE;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto done;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto done;
    if (EVP_DecryptUpdate(ctx, pt, &out_len, ct, (int)ct_len) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, (int)tag_len, (void *)tag) != 1) goto done;
    if (EVP_DecryptFinal_ex(ctx, pt + out_len, &final_len) != 1) goto done;

    *pt_len = (DWORD)(out_len + final_len);
    ok = TRUE;

done:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

BOOL crypto_init(CRYPTO_CTX *ctx, BYTE *pubkey_out, DWORD *pubkey_len) {
    if (!ctx || !pubkey_out || !pubkey_len || *pubkey_len == 0)
        return FALSE;

    if (g_ecdh_key) {
        EC_KEY_free(g_ecdh_key);
        g_ecdh_key = NULL;
    }

    memset(ctx, 0, sizeof(*ctx));

    if (RAND_bytes(ctx->send_nonce + CRYPTO_COUNTER_SIZE,
                   CRYPTO_NONCE_SIZE - CRYPTO_COUNTER_SIZE) != 1)
        return FALSE;
    if (RAND_bytes(ctx->recv_nonce + CRYPTO_COUNTER_SIZE,
                   CRYPTO_NONCE_SIZE - CRYPTO_COUNTER_SIZE) != 1)
        return FALSE;

    g_ecdh_key = ecdh_keygen();
    if (!g_ecdh_key) return FALSE;

    if (!ec_pubkey_to_bcrypt_blob(g_ecdh_key, pubkey_out, pubkey_len)) {
        EC_KEY_free(g_ecdh_key);
        g_ecdh_key = NULL;
        return FALSE;
    }

    ctx->send_counter = 0;
    ctx->recv_counter = 0;
    ctx->initialized = FALSE;
    return TRUE;
}

BOOL crypto_derive_session_key(CRYPTO_CTX *ctx, const BYTE *server_pubkey, DWORD server_pubkey_len) {
    if (!ctx || !server_pubkey || !g_ecdh_key) return FALSE;

    EC_KEY *peer = ec_pubkey_from_bcrypt_blob(server_pubkey, server_pubkey_len);
    if (!peer) return FALSE;

    const EC_POINT *peer_pub = EC_KEY_get0_public_key(peer);
    const EC_GROUP *group = EC_KEY_get0_group(g_ecdh_key);
    BOOL ok = FALSE;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    BYTE *secret = NULL;

    int field_size = EC_GROUP_get_degree(group);
    size_t secret_len = (field_size + 7) / 8;
    secret = (BYTE *)malloc(secret_len);
    if (!secret) goto done;

    int ret = ECDH_compute_key(secret, secret_len, peer_pub,
                               g_ecdh_key, NULL);
    if (ret <= 0) goto done;

    SHA256(secret, (size_t)ret, hash);
    memcpy(ctx->session_key, hash, CRYPTO_SESSION_KEY);
    ctx->initialized = TRUE;
    ok = TRUE;

done:
    if (secret) {
        secure_zero(secret, secret_len);
        free(secret);
    }
    EC_KEY_free(peer);
    if (ok) {
        EC_KEY_free(g_ecdh_key);
        g_ecdh_key = NULL;
    }
    return ok;
}

BYTE *crypto_encrypt(CRYPTO_CTX *ctx, const BYTE *plaintext, DWORD pt_len, DWORD *out_len) {
    if (!ctx || !ctx->initialized || !plaintext || !out_len) return NULL;

    ctx->send_counter++;
    store_be32(ctx->send_nonce, ctx->send_counter);

    BYTE tag[CRYPTO_TAG_SIZE];
    BYTE *ciphertext = (BYTE *)malloc(pt_len);
    if (!ciphertext) return NULL;

    DWORD ct_len = 0;
    if (!aes_gcm_encrypt(ctx->session_key, ctx->send_nonce, CRYPTO_NONCE_SIZE,
                         plaintext, pt_len, ciphertext, &ct_len, tag, CRYPTO_TAG_SIZE)) {
        free(ciphertext);
        return NULL;
    }

    DWORD pkt_len = CRYPTO_HEADER_SIZE + ct_len;
    DWORD wire_len = (ctx->has_session_id ? SESSION_ID_HASH_SIZE : 0) + pkt_len;
    BYTE *packet = (BYTE *)calloc(1, wire_len);
    if (!packet) {
        free(ciphertext);
        return NULL;
    }

    DWORD off = 0;
    if (ctx->has_session_id) {
        memcpy(packet, ctx->session_id_hash, SESSION_ID_HASH_SIZE);
        off = SESSION_ID_HASH_SIZE;
    }

    store_be32(packet + off, ctx->send_counter);
    memcpy(packet + off + CRYPTO_COUNTER_SIZE, ctx->send_nonce, CRYPTO_NONCE_SIZE);
    memcpy(packet + off + CRYPTO_COUNTER_SIZE + CRYPTO_NONCE_SIZE, tag, CRYPTO_TAG_SIZE);
    memcpy(packet + off + CRYPTO_HEADER_SIZE, ciphertext, ct_len);

    free(ciphertext);
    *out_len = wire_len;
    return packet;
}

BYTE *crypto_decrypt(CRYPTO_CTX *ctx, const BYTE *packet, DWORD pkt_len, DWORD *out_len) {
    if (!ctx || !ctx->initialized || !packet || !out_len) return NULL;

    DWORD off = 0;
    if (pkt_len > SESSION_ID_HASH_SIZE + CRYPTO_HEADER_SIZE &&
        ctx->has_session_id &&
        memcmp(packet, ctx->session_id_hash, SESSION_ID_HASH_SIZE) == 0) {
        off = SESSION_ID_HASH_SIZE;
    }

    if (pkt_len <= off + CRYPTO_HEADER_SIZE) return NULL;

    const BYTE *crypto_pkt = packet + off;
    DWORD crypto_len = pkt_len - off;

    DWORD counter = load_be32(crypto_pkt);
    if (counter <= ctx->recv_counter) return NULL;
    if (counter > ctx->recv_counter + MAX_COUNTER_GAP) return NULL;

    const BYTE *nonce = crypto_pkt + CRYPTO_COUNTER_SIZE;
    const BYTE *tag = crypto_pkt + CRYPTO_COUNTER_SIZE + CRYPTO_NONCE_SIZE;
    const BYTE *ciphertext = crypto_pkt + CRYPTO_HEADER_SIZE;
    DWORD ct_len = crypto_len - CRYPTO_HEADER_SIZE;

    BYTE *plaintext = (BYTE *)malloc(ct_len);
    if (!plaintext) return NULL;

    DWORD pt_len_out = 0;
    if (!aes_gcm_decrypt(ctx->session_key, nonce, CRYPTO_NONCE_SIZE,
                         ciphertext, ct_len, tag, CRYPTO_TAG_SIZE,
                         plaintext, &pt_len_out)) {
        free(plaintext);
        return NULL;
    }

    ctx->recv_counter = counter;
    memcpy(ctx->recv_nonce, nonce, CRYPTO_NONCE_SIZE);
    *out_len = pt_len_out;
    return plaintext;
}

void crypto_cleanup(CRYPTO_CTX *ctx) {
    if (g_ecdh_key) {
        EC_KEY_free(g_ecdh_key);
        g_ecdh_key = NULL;
    }
    if (ctx) {
        secure_zero(ctx->session_key, sizeof(ctx->session_key));
        secure_zero(ctx->send_nonce, sizeof(ctx->send_nonce));
        secure_zero(ctx->recv_nonce, sizeof(ctx->recv_nonce));
        secure_zero(ctx->session_id_hash, sizeof(ctx->session_id_hash));
        ctx->send_counter = 0;
        ctx->recv_counter = 0;
        ctx->initialized = FALSE;
        ctx->has_session_id = FALSE;
    }
}
