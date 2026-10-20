#include <stdio.h>
#include <stdlib.h>
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
    DWORD plen = (DWORD)strlen(pre);
    DWORD slen = (DWORD)strlen(suf);
    if (plen > 0 && in_len >= plen && memcmp(in, pre, plen) == 0) start = plen;
    if (slen > 0 && end > start + slen &&
        memcmp(in + end - slen, suf, slen) == 0) end -= slen;
    DWORD n = end - start;
    if (n > out_cap) n = out_cap;
    memcpy(out, in + start, n);
    return n;
}

DWORD malleable_encode_outbound(const BYTE *in, DWORD in_len, BYTE *out, DWORD out_cap) {
    DWORD alloc_sz = in_len < 4096 ? 8192 : in_len * 3;
    BYTE *tmp = (BYTE *)malloc(alloc_sz);
    if (!tmp) return 0;
    DWORD len = in_len;
    if (len > alloc_sz) len = alloc_sz;
    memcpy(tmp, in, len);

    xor_mask(tmp, len);

    if (MALLEABLE_OUT_BASE64) {
        DWORD b64_cap = len * 2 + 4;
        char *b64 = (char *)malloc(b64_cap);
        if (!b64) { free(tmp); return 0; }
        DWORD blen = b64_encode(tmp, len, b64, b64_cap);
        if (blen > alloc_sz) {
            BYTE *bigger = (BYTE *)realloc(tmp, blen + 1);
            if (!bigger) { free(b64); free(tmp); return 0; }
            tmp = bigger;
        }
        memcpy(tmp, b64, blen);
        len = blen;
        free(b64);
    }

    const char *pre = MALLEABLE_OUT_PREPEND;
    const char *suf = MALLEABLE_OUT_APPEND;
    DWORD plen = (DWORD)strlen(pre);
    DWORD slen = (DWORD)strlen(suf);
    if (plen + len + slen > out_cap) { free(tmp); return 0; }
    memcpy(out, pre, plen);
    memcpy(out + plen, tmp, len);
    memcpy(out + plen + len, suf, slen);
    free(tmp);
    return plen + len + slen;
}

DWORD malleable_decode_inbound(const BYTE *in, DWORD in_len, BYTE *out, DWORD out_cap) {
    DWORD alloc_sz = in_len < 4096 ? 8192 : in_len + 1024;
    BYTE *tmp = (BYTE *)malloc(alloc_sz);
    if (!tmp) return 0;
    DWORD len = strip_prefix_suffix(in, in_len, MALLEABLE_IN_PREPEND, MALLEABLE_IN_APPEND,
                                    tmp, alloc_sz);

    if (MALLEABLE_IN_BASE64) {
        BYTE *dec = (BYTE *)malloc(alloc_sz);
        if (!dec) { free(tmp); return 0; }
        len = b64_decode((const char *)tmp, len, dec, alloc_sz);
        memcpy(tmp, dec, len);
        free(dec);
    }

    xor_mask(tmp, len);
    if (len > out_cap) len = out_cap;
    memcpy(out, tmp, len);
    free(tmp);
    return len;
}

DWORD malleable_build_header_list(char headers[][256], DWORD max_count) {
    DWORD n = 0;
    if (n < max_count)
        snprintf(headers[n++], 256, "Accept: %s", HTTP_HDR_ACCEPT);
    if (n < max_count)
        snprintf(headers[n++], 256, "Accept-Language: %s", HTTP_HDR_ACCEPT_LANGUAGE);
    if (n < max_count)
        snprintf(headers[n++], 256, "Content-Type: application/json");
#ifdef CUSTOM_HEADER_0_KEY
    if (n < max_count)
        snprintf(headers[n++], 256, "%s: %s", CUSTOM_HEADER_0_KEY, CUSTOM_HEADER_0_VAL);
#endif
#ifdef CUSTOM_HEADER_1_KEY
    if (n < max_count)
        snprintf(headers[n++], 256, "%s: %s", CUSTOM_HEADER_1_KEY, CUSTOM_HEADER_1_VAL);
#endif
    return n;
}

void malleable_build_headers(char *buf, DWORD buf_size) {
    snprintf(buf, buf_size,
             "Accept: %s\r\nAccept-Language: %s\r\nContent-Type: application/json\r\n",
             HTTP_HDR_ACCEPT, HTTP_HDR_ACCEPT_LANGUAGE);
}
