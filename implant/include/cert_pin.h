#ifndef CERT_PIN_H
#define CERT_PIN_H

#ifdef CERT_PIN_HASH

#include <windows.h>
#include <winhttp.h>
#include <wincrypt.h>
#include <bcrypt.h>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")

#ifndef CERT_PIN_FAIL
#define CERT_PIN_FAIL 0
#endif

static BOOL cert_pin_hex_to_bytes(const char *hex, BYTE *out, DWORD out_len) {
    DWORD i;
    for (i = 0; i < out_len; i++) {
        char c1 = hex[i * 2];
        char c2 = hex[i * 2 + 1];
        if (!c1 || !c2) return FALSE;
        BYTE n1 = (c1 >= '0' && c1 <= '9') ? (BYTE)(c1 - '0') :
                  (c1 >= 'a' && c1 <= 'f') ? (BYTE)(c1 - 'a' + 10) :
                  (c1 >= 'A' && c1 <= 'F') ? (BYTE)(c1 - 'A' + 10) : 0xFF;
        BYTE n2 = (c2 >= '0' && c2 <= '9') ? (BYTE)(c2 - '0') :
                  (c2 >= 'a' && c2 <= 'f') ? (BYTE)(c2 - 'a' + 10) :
                  (c2 >= 'A' && c2 <= 'F') ? (BYTE)(c2 - 'A' + 10) : 0xFF;
        if (n1 > 0x0F || n2 > 0x0F) return FALSE;
        out[i] = (BYTE)((n1 << 4) | n2);
    }
    return TRUE;
}

static BOOL cert_pin_b64_decode(const char *b64, BYTE *out, DWORD *out_len) {
    DWORD need = 0;
    if (!CryptStringToBinaryA(b64, 0, CRYPT_STRING_BASE64, NULL, &need, NULL, NULL))
        return FALSE;
    if (need > *out_len) return FALSE;
    return CryptStringToBinaryA(b64, 0, CRYPT_STRING_BASE64, out, out_len, NULL, NULL);
}

static BOOL cert_pin_hash_spki(PCCERT_CONTEXT pCtx, BYTE hash[32]) {
    PCERT_PUBLIC_KEY_INFO pInfo = &pCtx->pCertInfo->SubjectPublicKeyInfo;
    DWORD cbEncoded = 0;

    if (!CryptEncodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                             X509_PUBLIC_KEY_INFO, pInfo, 0, NULL, NULL, &cbEncoded))
        return FALSE;

    BYTE *pbEncoded = (BYTE *)HeapAlloc(GetProcessHeap(), 0, cbEncoded);
    if (!pbEncoded) return FALSE;

    if (!CryptEncodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                             X509_PUBLIC_KEY_INFO, pInfo, 0, NULL, pbEncoded, &cbEncoded)) {
        HeapFree(GetProcessHeap(), 0, pbEncoded);
        return FALSE;
    }

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    BOOL ok = FALSE;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0) != 0)
        goto cleanup;
    if (BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0) != 0)
        goto cleanup;
    if (BCryptHashData(hHash, pbEncoded, cbEncoded, 0) != 0)
        goto cleanup;
    if (BCryptFinishHash(hHash, hash, 32, 0) != 0)
        goto cleanup;
    ok = TRUE;

cleanup:
    if (hHash) BCryptDestroyHash(hHash);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    HeapFree(GetProcessHeap(), 0, pbEncoded);
    return ok;
}

static BOOL cert_pin_entry_matches(const char *entry, const BYTE hash[32]) {
    while (*entry == ' ' || *entry == ',') entry++;
    if (!*entry) return FALSE;

    if (strncmp(entry, "sha256//", 8) == 0) {
        const char *b64 = entry + 8;
        BYTE decoded[32];
        DWORD dlen = 32;
        if (!cert_pin_b64_decode(b64, decoded, &dlen) || dlen != 32)
            return FALSE;
        return memcmp(decoded, hash, 32) == 0;
    }

    if (strlen(entry) == 64) {
        BYTE hexhash[32];
        if (!cert_pin_hex_to_bytes(entry, hexhash, 32))
            return FALSE;
        return memcmp(hexhash, hash, 32) == 0;
    }

    return FALSE;
}

static BOOL cert_pin_matches(PCCERT_CONTEXT pCtx) {
    BYTE hash[32];
    const char *p = CERT_PIN_HASH;

    if (!cert_pin_hash_spki(pCtx, hash))
        return FALSE;

    while (*p) {
        char token[256];
        size_t i = 0;

        while (*p == ' ' || *p == ',') p++;
        if (!*p) break;

        while (*p && *p != ',' && i + 1 < sizeof(token))
            token[i++] = *p++;
        token[i] = '\0';

        if (i > 0 && cert_pin_entry_matches(token, hash))
            return TRUE;
    }
    return FALSE;
}

static volatile LONG g_cert_pin_fail = 0;

static void CALLBACK cert_pin_callback(HINTERNET hInternet, DWORD_PTR dwContext,
                                       DWORD dwInternetStatus,
                                       LPVOID lpvStatusInformation,
                                       DWORD dwStatusInformationLength) {
    (void)dwContext;
    (void)lpvStatusInformation;
    (void)dwStatusInformationLength;

    if (dwInternetStatus != WINHTTP_CALLBACK_STATUS_SENDREQUEST_COMPLETE &&
        dwInternetStatus != WINHTTP_CALLBACK_STATUS_SECURE_FAILURE)
        return;

    PCCERT_CONTEXT pCert = NULL;
    DWORD cb = sizeof(pCert);
    if (!WinHttpQueryOption(hInternet, WINHTTP_OPTION_SERVER_CERT_CONTEXT, &pCert, &cb)) {
        InterlockedExchange(&g_cert_pin_fail, 1);
        return;
    }
    if (!cert_pin_matches(pCert))
        InterlockedExchange(&g_cert_pin_fail, 1);
    CertFreeCertificateContext(pCert);
}

static void cert_pin_reset(void) {
    InterlockedExchange(&g_cert_pin_fail, 0);
}

static BOOL cert_pin_failed(void) {
    return InterlockedCompareExchange(&g_cert_pin_fail, 0, 0) != 0;
}

static void cert_pin_install_callback(HINTERNET hRequest) {
    cert_pin_reset();
    WinHttpSetStatusCallback(
        hRequest,
        cert_pin_callback,
        WINHTTP_CALLBACK_FLAG_SENDREQUEST_COMPLETE | WINHTTP_CALLBACK_FLAG_SECURE_FAILURE,
        0);
}

static void cert_pin_apply_tls_flags(HINTERNET hRequest) {
    /* Pin-only mode: skip CA/CN/date checks; SPKI pin enforced in callback */
    DWORD secFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                     SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                     SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
    WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &secFlags, sizeof(secFlags));
}

#endif /* CERT_PIN_HASH */

#endif /* CERT_PIN_H */
