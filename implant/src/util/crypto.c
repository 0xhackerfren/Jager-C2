#include <windows.h>
#include <bcrypt.h>
#include <string.h>
#include "../../include/crypto.h"

#pragma comment(lib, "bcrypt.lib")

#define CRYPTO_COUNTER_SIZE  4
#define CRYPTO_NONCE_SIZE    12
#define CRYPTO_TAG_SIZE      16
#define CRYPTO_HEADER_SIZE   (CRYPTO_COUNTER_SIZE + CRYPTO_NONCE_SIZE + CRYPTO_TAG_SIZE)
#define CRYPTO_SESSION_KEY   32

static BCRYPT_ALG_HANDLE g_ecdh_alg = NULL;
static BCRYPT_KEY_HANDLE g_ecdh_priv = NULL;

static void secure_zero(BYTE *buf, DWORD len) {
    if (buf && len > 0)
        SecureZeroMemory(buf, len);
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
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    BYTE hash[32];
    DWORD cb_data = 0, cb_obj = 0;
    BYTE *obj = NULL;
    BOOL ok = FALSE;

    if (!session_id || !session_id[0] || !out)
        return FALSE;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0) != 0)
        return FALSE;

    if (BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cb_obj,
                          sizeof(cb_obj), &cb_data, 0) != 0)
        goto done;

    obj = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cb_obj);
    if (!obj)
        goto done;

    if (BCryptCreateHash(hAlg, &hHash, obj, cb_obj, NULL, 0, 0) != 0)
        goto done;

    if (BCryptHashData(hHash, (PUCHAR)session_id, (ULONG)lstrlenA(session_id), 0) != 0)
        goto done;

    if (BCryptFinishHash(hHash, hash, sizeof(hash), 0) != 0)
        goto done;

    CopyMemory(out, hash, SESSION_ID_HASH_SIZE);
    ok = TRUE;

done:
    if (hHash)
        BCryptDestroyHash(hHash);
    if (obj)
        HeapFree(GetProcessHeap(), 0, obj);
    if (hAlg)
        BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

void crypto_set_session_id(CRYPTO_CTX *ctx, const char *session_id) {
    if (!ctx || !session_id)
        return;
    if (sha256_trunc8(session_id, ctx->session_id_hash))
        ctx->has_session_id = TRUE;
}

static void destroy_ecdh_handles(void) {
    if (g_ecdh_priv) {
        BCryptDestroyKey(g_ecdh_priv);
        g_ecdh_priv = NULL;
    }
    if (g_ecdh_alg) {
        BCryptCloseAlgorithmProvider(g_ecdh_alg, 0);
        g_ecdh_alg = NULL;
    }
}

static BOOL aes_gcm_encrypt(const BYTE *key, const BYTE *nonce, DWORD nonce_len,
                            const BYTE *pt, DWORD pt_len,
                            BYTE *ct, DWORD *ct_len, BYTE *tag, DWORD tag_len) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    BYTE *key_obj = NULL;
    BOOL ok = FALSE;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0) != 0)
        return FALSE;

    if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                          (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                          (ULONG)(sizeof(BCRYPT_CHAIN_MODE_GCM)), 0) != 0)
        goto done;

    DWORD cb_obj = 0, cb_data = 0;
    if (BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cb_obj,
                          sizeof(cb_obj), &cb_data, 0) != 0)
        goto done;

    key_obj = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cb_obj);
    if (!key_obj)
        goto done;

    if (BCryptGenerateSymmetricKey(hAlg, &hKey, key_obj, cb_obj,
                                   (PUCHAR)key, CRYPTO_SESSION_KEY, 0) != 0)
        goto done;

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info;
    BCRYPT_INIT_AUTH_MODE_INFO(auth_info);
    auth_info.pbNonce = (PUCHAR)nonce;
    auth_info.cbNonce = nonce_len;
    auth_info.pbTag = tag;
    auth_info.cbTag = tag_len;

    DWORD out_len = 0;
    if (BCryptEncrypt(hKey, (PUCHAR)pt, pt_len, &auth_info, NULL, 0,
                      ct, pt_len, &out_len, 0) == 0) {
        *ct_len = out_len;
        ok = TRUE;
    }

done:
    if (hKey)
        BCryptDestroyKey(hKey);
    if (key_obj)
        HeapFree(GetProcessHeap(), 0, key_obj);
    if (hAlg)
        BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

static BOOL aes_gcm_decrypt(const BYTE *key, const BYTE *nonce, DWORD nonce_len,
                            const BYTE *ct, DWORD ct_len,
                            const BYTE *tag, DWORD tag_len,
                            BYTE *pt, DWORD *pt_len) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    BYTE *key_obj = NULL;
    BOOL ok = FALSE;
    BYTE tag_copy[CRYPTO_TAG_SIZE];

    if (tag_len > sizeof(tag_copy))
        return FALSE;
    CopyMemory(tag_copy, tag, tag_len);

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0) != 0)
        return FALSE;

    if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                          (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                          (ULONG)(sizeof(BCRYPT_CHAIN_MODE_GCM)), 0) != 0)
        goto done;

    DWORD cb_obj = 0, cb_data = 0;
    if (BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cb_obj,
                          sizeof(cb_obj), &cb_data, 0) != 0)
        goto done;

    key_obj = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cb_obj);
    if (!key_obj)
        goto done;

    if (BCryptGenerateSymmetricKey(hAlg, &hKey, key_obj, cb_obj,
                                   (PUCHAR)key, CRYPTO_SESSION_KEY, 0) != 0)
        goto done;

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info;
    BCRYPT_INIT_AUTH_MODE_INFO(auth_info);
    auth_info.pbNonce = (PUCHAR)nonce;
    auth_info.cbNonce = nonce_len;
    auth_info.pbTag = tag_copy;
    auth_info.cbTag = tag_len;

    DWORD out_len = 0;
    if (BCryptDecrypt(hKey, (PUCHAR)ct, ct_len, &auth_info, NULL, 0,
                       pt, ct_len, &out_len, 0) == 0) {
        *pt_len = out_len;
        ok = TRUE;
    }

done:
    secure_zero(tag_copy, sizeof(tag_copy));
    if (hKey)
        BCryptDestroyKey(hKey);
    if (key_obj)
        HeapFree(GetProcessHeap(), 0, key_obj);
    if (hAlg)
        BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

BOOL crypto_init(CRYPTO_CTX *ctx, BYTE *pubkey_out, DWORD *pubkey_len) {
    if (!ctx || !pubkey_out || !pubkey_len || *pubkey_len == 0)
        return FALSE;

    destroy_ecdh_handles();
    ZeroMemory(ctx, sizeof(*ctx));

    if (BCryptGenRandom(NULL, ctx->send_nonce + CRYPTO_COUNTER_SIZE,
                        CRYPTO_NONCE_SIZE - CRYPTO_COUNTER_SIZE,
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
        return FALSE;

    if (BCryptGenRandom(NULL, ctx->recv_nonce + CRYPTO_COUNTER_SIZE,
                        CRYPTO_NONCE_SIZE - CRYPTO_COUNTER_SIZE,
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
        return FALSE;

    if (BCryptOpenAlgorithmProvider(&g_ecdh_alg, BCRYPT_ECDH_P256_ALGORITHM, NULL, 0) != 0)
        return FALSE;

    if (BCryptGenerateKeyPair(g_ecdh_alg, &g_ecdh_priv, 256, 0) != 0) {
        destroy_ecdh_handles();
        return FALSE;
    }

    if (BCryptFinalizeKeyPair(g_ecdh_priv, 0) != 0) {
        destroy_ecdh_handles();
        return FALSE;
    }

    DWORD exported = 0;
    if (BCryptExportKey(g_ecdh_priv, NULL, BCRYPT_ECCPUBLIC_BLOB,
                        pubkey_out, *pubkey_len, &exported, 0) != 0) {
        destroy_ecdh_handles();
        return FALSE;
    }

    *pubkey_len = exported;
    ctx->send_counter = 0;
    ctx->recv_counter = 0;
    ctx->initialized = FALSE;
    return TRUE;
}

BOOL crypto_derive_session_key(CRYPTO_CTX *ctx, const BYTE *server_pubkey, DWORD server_pubkey_len) {
    BCRYPT_KEY_HANDLE h_peer = NULL;
    BCRYPT_SECRET_HANDLE h_secret = NULL;
    BOOL ok = FALSE;

    if (!ctx || !server_pubkey || server_pubkey_len == 0 || !g_ecdh_alg || !g_ecdh_priv)
        return FALSE;

    if (BCryptImportKeyPair(g_ecdh_alg, NULL, BCRYPT_ECCPUBLIC_BLOB, &h_peer,
                            (PUCHAR)server_pubkey, server_pubkey_len, 0) != 0)
        return FALSE;

    if (BCryptSecretAgreement(g_ecdh_priv, h_peer, &h_secret, 0) != 0)
        goto done;

    BCryptBuffer param_buf;
    param_buf.cbBuffer = (ULONG)(sizeof(BCRYPT_SHA256_ALGORITHM));
    param_buf.BufferType = KDF_HASH_ALGORITHM;
    param_buf.pvBuffer = (PVOID)BCRYPT_SHA256_ALGORITHM;

    BCryptBufferDesc param_desc;
    param_desc.ulVersion = BCRYPTBUFFER_VERSION;
    param_desc.cBuffers = 1;
    param_desc.pBuffers = &param_buf;

    DWORD derived_len = 0;
    if (BCryptDeriveKey(h_secret, BCRYPT_KDF_HASH, &param_desc,
                        ctx->session_key, CRYPTO_SESSION_KEY,
                        &derived_len, 0) != 0)
        goto done;

    if (derived_len != CRYPTO_SESSION_KEY)
        goto done;

    ctx->initialized = TRUE;
    ok = TRUE;

done:
    if (h_secret)
        BCryptDestroySecret(h_secret);
    if (h_peer)
        BCryptDestroyKey(h_peer);
    destroy_ecdh_handles();
    return ok;
}

BYTE *crypto_encrypt(CRYPTO_CTX *ctx, const BYTE *plaintext, DWORD pt_len, DWORD *out_len) {
    if (!ctx || !ctx->initialized || !plaintext || !out_len)
        return NULL;

    ctx->send_counter++;
    store_be32(ctx->send_nonce, ctx->send_counter);

    BYTE tag[CRYPTO_TAG_SIZE];
    BYTE *ciphertext = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pt_len);
    if (!ciphertext)
        return NULL;

    DWORD ct_len = 0;
    if (!aes_gcm_encrypt(ctx->session_key, ctx->send_nonce, CRYPTO_NONCE_SIZE,
                         plaintext, pt_len, ciphertext, &ct_len, tag, CRYPTO_TAG_SIZE)) {
        HeapFree(GetProcessHeap(), 0, ciphertext);
        return NULL;
    }

    DWORD pkt_len = CRYPTO_HEADER_SIZE + ct_len;
    DWORD wire_len = (ctx->has_session_id ? SESSION_ID_HASH_SIZE : 0) + pkt_len;
    BYTE *packet = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, wire_len);
    if (!packet) {
        HeapFree(GetProcessHeap(), 0, ciphertext);
        return NULL;
    }

    DWORD off = 0;
    if (ctx->has_session_id) {
        CopyMemory(packet, ctx->session_id_hash, SESSION_ID_HASH_SIZE);
        off = SESSION_ID_HASH_SIZE;
    }

    store_be32(packet + off, ctx->send_counter);
    CopyMemory(packet + off + CRYPTO_COUNTER_SIZE, ctx->send_nonce, CRYPTO_NONCE_SIZE);
    CopyMemory(packet + off + CRYPTO_COUNTER_SIZE + CRYPTO_NONCE_SIZE, tag, CRYPTO_TAG_SIZE);
    CopyMemory(packet + off + CRYPTO_HEADER_SIZE, ciphertext, ct_len);

    HeapFree(GetProcessHeap(), 0, ciphertext);
    *out_len = wire_len;
    return packet;
}

BYTE *crypto_decrypt(CRYPTO_CTX *ctx, const BYTE *packet, DWORD pkt_len, DWORD *out_len) {
    if (!ctx || !ctx->initialized || !packet || !out_len)
        return NULL;

    DWORD off = 0;
    if (pkt_len > SESSION_ID_HASH_SIZE + CRYPTO_HEADER_SIZE &&
        ctx->has_session_id &&
        memcmp(packet, ctx->session_id_hash, SESSION_ID_HASH_SIZE) == 0) {
        off = SESSION_ID_HASH_SIZE;
    }

    if (pkt_len <= off + CRYPTO_HEADER_SIZE)
        return NULL;

    const BYTE *crypto_pkt = packet + off;
    DWORD crypto_len = pkt_len - off;

    DWORD counter = load_be32(crypto_pkt);
    if (counter <= ctx->recv_counter)
        return NULL;
    if (counter > ctx->recv_counter + MAX_COUNTER_GAP)
        return NULL;

    const BYTE *nonce = crypto_pkt + CRYPTO_COUNTER_SIZE;
    const BYTE *tag = crypto_pkt + CRYPTO_COUNTER_SIZE + CRYPTO_NONCE_SIZE;
    const BYTE *ciphertext = crypto_pkt + CRYPTO_HEADER_SIZE;
    DWORD ct_len = crypto_len - CRYPTO_HEADER_SIZE;

    BYTE *plaintext = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ct_len);
    if (!plaintext)
        return NULL;

    DWORD pt_len = 0;
    if (!aes_gcm_decrypt(ctx->session_key, nonce, CRYPTO_NONCE_SIZE,
                         ciphertext, ct_len, tag, CRYPTO_TAG_SIZE,
                         plaintext, &pt_len)) {
        HeapFree(GetProcessHeap(), 0, plaintext);
        return NULL;
    }

    ctx->recv_counter = counter;
    CopyMemory(ctx->recv_nonce, nonce, CRYPTO_NONCE_SIZE);

    *out_len = pt_len;
    return plaintext;
}

void crypto_cleanup(CRYPTO_CTX *ctx) {
    destroy_ecdh_handles();
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

BOOL crypto_hmac_trunc8(const BYTE *key, DWORD key_len,
                        const BYTE *data, DWORD data_len,
                        BYTE out[8]) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    BYTE hash[32];
    DWORD hash_len = 0, cb_data = 0, cb_obj = 0;
    BYTE *hash_obj = NULL;
    BOOL ok = FALSE;

    if (!key || key_len == 0 || !data || !out)
        return FALSE;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL,
                                    BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0)
        return FALSE;

    if (BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cb_obj,
                          sizeof(cb_obj), &cb_data, 0) != 0)
        goto done;

    hash_obj = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cb_obj);
    if (!hash_obj)
        goto done;

    if (BCryptCreateHash(hAlg, &hHash, hash_obj, cb_obj, (PUCHAR)key, key_len, 0) != 0)
        goto done;

    if (BCryptHashData(hHash, (PUCHAR)data, data_len, 0) != 0)
        goto done;

    hash_len = sizeof(hash);
    if (BCryptFinishHash(hHash, hash, hash_len, 0) != 0)
        goto done;

    CopyMemory(out, hash, 8);
    ok = TRUE;

done:
    if (hHash)
        BCryptDestroyHash(hHash);
    if (hash_obj)
        HeapFree(GetProcessHeap(), 0, hash_obj);
    if (hAlg)
        BCryptCloseAlgorithmProvider(hAlg, 0);
    secure_zero(hash, sizeof(hash));
    return ok;
}
