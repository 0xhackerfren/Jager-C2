#include <windows.h>
#include "../../include/base64.h"

static const char b64_enc_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static const signed char b64_dec_table[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
    52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
    15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
    -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
    41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
};

DWORD b64_encode(const BYTE *in, DWORD in_len, char *out, DWORD out_cap) {
    DWORD o = 0;
    for (DWORD i = 0; i < in_len; i += 3) {
        if (o + 4 >= out_cap) break;
        DWORD n = ((DWORD)in[i] << 16);
        if (i + 1 < in_len) n |= ((DWORD)in[i + 1] << 8);
        if (i + 2 < in_len) n |= in[i + 2];
        out[o++] = b64_enc_table[(n >> 18) & 0x3F];
        out[o++] = b64_enc_table[(n >> 12) & 0x3F];
        out[o++] = (i + 1 < in_len) ? b64_enc_table[(n >> 6) & 0x3F] : '=';
        out[o++] = (i + 2 < in_len) ? b64_enc_table[n & 0x3F] : '=';
    }
    if (o < out_cap) out[o] = '\0';
    return o;
}

DWORD b64_decode(const char *in, DWORD in_len, BYTE *out, DWORD out_cap) {
    DWORD o = 0, bits = 0, acc = 0;
    for (DWORD i = 0; i < in_len && o < out_cap; i++) {
        signed char v = b64_dec_table[(unsigned char)in[i]];
        if (v < 0) continue;
        acc = (acc << 6) | (unsigned)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[o++] = (BYTE)((acc >> bits) & 0xFF);
        }
    }
    return o;
}
