#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "../../include/json.h"

/* --- Parsing --- */

const char *json_skip_ws(const char *p) {
    while (*p == ' ' || *p == '\n' || *p == '\r' || *p == '\t') p++;
    return p;
}

static void json_unescape_copy(const char *start, const char *end, char *out, DWORD out_size) {
    DWORD o = 0;
    for (const char *p = start; p < end && o + 1 < out_size; p++) {
        if (*p == '\\' && p + 1 < end) {
            p++;
            switch (*p) {
            case '"':  out[o++] = '"'; break;
            case '\\': out[o++] = '\\'; break;
            case '/':  out[o++] = '/'; break;
            case 'b':  out[o++] = '\b'; break;
            case 'f':  out[o++] = '\f'; break;
            case 'n':  out[o++] = '\n'; break;
            case 'r':  out[o++] = '\r'; break;
            case 't':  out[o++] = '\t'; break;
            case 'u':
                if (p + 4 < end) {
                    unsigned int cp = 0;
                    for (int i = 0; i < 4; i++) {
                        char c = p[1 + i];
                        cp <<= 4;
                        if (c >= '0' && c <= '9') cp |= (unsigned)(c - '0');
                        else if (c >= 'a' && c <= 'f') cp |= (unsigned)(c - 'a' + 10);
                        else if (c >= 'A' && c <= 'F') cp |= (unsigned)(c - 'A' + 10);
                    }
                    p += 4;
                    if (cp <= 0x7F) out[o++] = (char)cp;
                }
                break;
            default:
                out[o++] = *p;
                break;
            }
        } else {
            out[o++] = *p;
        }
    }
    if (o < out_size) out[o] = '\0';
    else if (out_size > 0) out[out_size - 1] = '\0';
}

const char *json_find_string(const char *json, const char *key,
                             char *out, DWORD out_size) {
    char search[128];
    int n = _snprintf(search, sizeof(search), "\"%s\":\"", key);
    if (n < 0 || (DWORD)n >= sizeof(search)) return NULL;

    const char *start = strstr(json, search);
    if (!start) return NULL;
    start += n;

    const char *p = start;
    while (*p) {
        if (*p == '\\' && p[1]) {
            p += 2;
            continue;
        }
        if (*p == '"') break;
        p++;
    }
    if (*p != '"') return NULL;

    json_unescape_copy(start, p, out, out_size);
    return p + 1;
}

const char *json_find_int(const char *json, const char *key, int *out) {
    char search[128];
    int n = _snprintf(search, sizeof(search), "\"%s\":", key);
    if (n < 0 || (DWORD)n >= sizeof(search)) return NULL;

    const char *start = strstr(json, search);
    if (!start) return NULL;
    start += n;
    while (*start == ' ') start++;
    *out = 0;
    BOOL neg = FALSE;
    if (*start == '-') { neg = TRUE; start++; }
    while (*start >= '0' && *start <= '9') {
        *out = (*out * 10) + (*start - '0');
        start++;
    }
    if (neg) *out = -(*out);
    return start;
}

DWORD json_find_uint(const char *obj, const char *key) {
    int v = 0;
    json_find_int(obj, key, &v);
    return (v < 0) ? 0 : (DWORD)v;
}

const char *json_find_object_end(const char *start, const char *json_end) {
    if (!start || *start != '{') return NULL;

    int depth = 0;
    int in_string = 0;
    const char *p = start;

    while (*p && (!json_end || p <= json_end)) {
        if (in_string) {
            if (*p == '\\' && p[1]) {
                p += 2;
                continue;
            }
            if (*p == '"') in_string = 0;
            p++;
            continue;
        }

        if (*p == '"') {
            in_string = 1;
            p++;
            continue;
        }
        if (*p == '{') depth++;
        else if (*p == '}') {
            depth--;
            if (depth == 0) return p;
        }
        p++;
    }
    return NULL;
}
