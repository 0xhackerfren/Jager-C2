/**
 * json_emit.c - Safe JSON string emitter
 * Escapes all characters that are invalid in JSON strings:
 * " -> \"    \ -> \\    \n -> \n    \r -> \r    \t -> \t
 * Control chars (0x00-0x1F) -> \uXXXX
 */

#include <stdio.h>
#include <string.h>
#include "../../include/json.h"

int json_emit_string(char *buf, int cap, const char *value) {
    if (!buf || cap < 2) return -1;
    if (!value) value = "";

    int o = 0;
    buf[o++] = '"';
    for (const unsigned char *p = (const unsigned char *)value; *p; p++) {
        unsigned char c = *p;
        char esc[7];
        const char *insert = NULL;
        int insert_len = 0;

        switch (c) {
        case '"':
            insert = "\\\"";
            insert_len = 2;
            break;
        case '\\':
            insert = "\\\\";
            insert_len = 2;
            break;
        case '\b':
            insert = "\\b";
            insert_len = 2;
            break;
        case '\f':
            insert = "\\f";
            insert_len = 2;
            break;
        case '\n':
            insert = "\\n";
            insert_len = 2;
            break;
        case '\r':
            insert = "\\r";
            insert_len = 2;
            break;
        case '\t':
            insert = "\\t";
            insert_len = 2;
            break;
        default:
            if (c < 0x20) {
                insert_len = snprintf(esc, sizeof(esc), "\\u%04x", c);
                insert = esc;
            }
            break;
        }

        if (insert) {
            if (o + insert_len + 1 >= cap) return -1;
            memcpy(buf + o, insert, (size_t)insert_len);
            o += insert_len;
        } else {
            if (o + 2 >= cap) return -1;
            buf[o++] = (char)c;
        }
    }

    if (o + 1 >= cap) return -1;
    buf[o++] = '"';
    return o;
}

int json_emit_kv(char *buf, int cap, const char *key, const char *value) {
    if (!buf || cap < 4 || !key) return -1;

    int n = snprintf(buf, (size_t)cap, "\"%s\":", key);
    if (n < 0 || n >= cap) return -1;

    int vn = json_emit_string(buf + n, cap - n, value);
    if (vn < 0) return -1;
    return n + vn;
}

int json_emit_kv_int(char *buf, int cap, const char *key, int value) {
    if (!buf || cap < 8 || !key) return -1;
    int n = snprintf(buf, (size_t)cap, "\"%s\":%d", key, value);
    if (n < 0 || n >= cap) return -1;
    return n;
}

int json_emit_kv_bool(char *buf, int cap, const char *key, int value) {
    if (!buf || cap < 8 || !key) return -1;
    int n = snprintf(buf, (size_t)cap, "\"%s\":%s", key, value ? "true" : "false");
    if (n < 0 || n >= cap) return -1;
    return n;
}

int json_emit_kv_raw(char *buf, int cap, const char *key, const char *raw_json) {
    if (!buf || cap < 4 || !key) return -1;
    if (!raw_json) raw_json = "null";
    int n = snprintf(buf, (size_t)cap, "\"%s\":%s", key, raw_json);
    if (n < 0 || n >= cap) return -1;
    return n;
}
