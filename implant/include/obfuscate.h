#ifndef JAGER_OBFUSCATE_H
#define JAGER_OBFUSCATE_H

#include <windows.h>

#ifndef OBF_KEY
#define OBF_KEY 0x42
#endif

/*
 * Stack-based string decrypt: copies to stack buffer, XORs, returns pointer.
 * Usage: char buf[32]; char *s = DEOBF(buf, enc_literal, len);
 * The polymorphic engine pre-XORs string literals at build time with OBF_KEY.
 */
static inline void obf_decrypt(char *buf, const char *enc, int len) {
    for (int i = 0; i < len; i++) {
        buf[i] = (char)(enc[i] ^ (char)(OBF_KEY ^ (i & 0xFF)));
    }
    buf[len] = '\0';
}

#define DEOBF(buf, enc, len) (obf_decrypt((buf), (enc), (len)), (buf))

/* Compile-time byte encryption for OBF() macro (GCC/MinGW statement expressions). */
#define _OBF_B(i, c) ((char)((unsigned char)(c) ^ (unsigned char)(OBF_KEY ^ ((unsigned)(i) & 0xFFU))))

#define _OBF_AT(str, n) \
    ((sizeof(str) > ((n) + 1)) ? _OBF_B((n), (str)[(n)]) : (char)0)

#define _OBF128(s) \
    _OBF_AT(s,0),  _OBF_AT(s,1),  _OBF_AT(s,2),  _OBF_AT(s,3),  \
    _OBF_AT(s,4),  _OBF_AT(s,5),  _OBF_AT(s,6),  _OBF_AT(s,7),  \
    _OBF_AT(s,8),  _OBF_AT(s,9),  _OBF_AT(s,10), _OBF_AT(s,11), \
    _OBF_AT(s,12), _OBF_AT(s,13), _OBF_AT(s,14), _OBF_AT(s,15), \
    _OBF_AT(s,16), _OBF_AT(s,17), _OBF_AT(s,18), _OBF_AT(s,19), \
    _OBF_AT(s,20), _OBF_AT(s,21), _OBF_AT(s,22), _OBF_AT(s,23), \
    _OBF_AT(s,24), _OBF_AT(s,25), _OBF_AT(s,26), _OBF_AT(s,27), \
    _OBF_AT(s,28), _OBF_AT(s,29), _OBF_AT(s,30), _OBF_AT(s,31), \
    _OBF_AT(s,32), _OBF_AT(s,33), _OBF_AT(s,34), _OBF_AT(s,35), \
    _OBF_AT(s,36), _OBF_AT(s,37), _OBF_AT(s,38), _OBF_AT(s,39), \
    _OBF_AT(s,40), _OBF_AT(s,41), _OBF_AT(s,42), _OBF_AT(s,43), \
    _OBF_AT(s,44), _OBF_AT(s,45), _OBF_AT(s,46), _OBF_AT(s,47), \
    _OBF_AT(s,48), _OBF_AT(s,49), _OBF_AT(s,50), _OBF_AT(s,51), \
    _OBF_AT(s,52), _OBF_AT(s,53), _OBF_AT(s,54), _OBF_AT(s,55), \
    _OBF_AT(s,56), _OBF_AT(s,57), _OBF_AT(s,58), _OBF_AT(s,59), \
    _OBF_AT(s,60), _OBF_AT(s,61), _OBF_AT(s,62), _OBF_AT(s,63), \
    _OBF_AT(s,64), _OBF_AT(s,65), _OBF_AT(s,66), _OBF_AT(s,67), \
    _OBF_AT(s,68), _OBF_AT(s,69), _OBF_AT(s,70), _OBF_AT(s,71), \
    _OBF_AT(s,72), _OBF_AT(s,73), _OBF_AT(s,74), _OBF_AT(s,75), \
    _OBF_AT(s,76), _OBF_AT(s,77), _OBF_AT(s,78), _OBF_AT(s,79), \
    _OBF_AT(s,80), _OBF_AT(s,81), _OBF_AT(s,82), _OBF_AT(s,83), \
    _OBF_AT(s,84), _OBF_AT(s,85), _OBF_AT(s,86), _OBF_AT(s,87), \
    _OBF_AT(s,88), _OBF_AT(s,89), _OBF_AT(s,90), _OBF_AT(s,91), \
    _OBF_AT(s,92), _OBF_AT(s,93), _OBF_AT(s,94), _OBF_AT(s,95), \
    _OBF_AT(s,96), _OBF_AT(s,97), _OBF_AT(s,98), _OBF_AT(s,99), \
    _OBF_AT(s,100), _OBF_AT(s,101), _OBF_AT(s,102), _OBF_AT(s,103), \
    _OBF_AT(s,104), _OBF_AT(s,105), _OBF_AT(s,106), _OBF_AT(s,107), \
    _OBF_AT(s,108), _OBF_AT(s,109), _OBF_AT(s,110), _OBF_AT(s,111), \
    _OBF_AT(s,112), _OBF_AT(s,113), _OBF_AT(s,114), _OBF_AT(s,115), \
    _OBF_AT(s,116), _OBF_AT(s,117), _OBF_AT(s,118), _OBF_AT(s,119), \
    _OBF_AT(s,120), _OBF_AT(s,121), _OBF_AT(s,122), _OBF_AT(s,123), \
    _OBF_AT(s,124), _OBF_AT(s,125), _OBF_AT(s,126), _OBF_AT(s,127)

/*
 * OBF(str) - compile-time encrypted string literal, decrypted into static storage.
 * Safe to store the returned pointer for the process lifetime.
 */
#define OBF(str) _OBF_UNIQUE(str, __COUNTER__)

#define _OBF_UNIQUE(str, id) _OBF_BODY(str, id)
#define _OBF_BODY(str, id) \
    ({ \
        enum { _obf_len_##id = (int)(sizeof(str) - 1) }; \
        static const char _obf_enc_##id[128] = { _OBF128(str) }; \
        static char _obf_buf_##id[128]; \
        obf_decrypt(_obf_buf_##id, _obf_enc_##id, _obf_len_##id); \
        _obf_buf_##id; \
    })

#endif /* JAGER_OBFUSCATE_H */
