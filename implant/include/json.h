#ifndef JAGER_JSON_H
#define JAGER_JSON_H

#include <windows.h>

/*
 * Bounded JSON parsing and emission. All output functions use snprintf
 * and return bytes written (excluding NUL), or -1 on truncation.
 */

/* --- Parsing --- */

const char *json_find_string(const char *json, const char *key,
                             char *out, DWORD out_size);

const char *json_find_int(const char *json, const char *key, int *out);

const char *json_skip_ws(const char *p);

DWORD json_find_uint(const char *obj, const char *key);

/* Find matching '}' for object starting at 'start'. Optional json_end bounds scan. */
const char *json_find_object_end(const char *start, const char *json_end);

/* --- Emission (json_emit.c) --- */

int json_emit_string(char *buf, int cap, const char *value);
int json_emit_kv(char *buf, int cap, const char *key, const char *value);
int json_emit_kv_int(char *buf, int cap, const char *key, int value);
int json_emit_kv_bool(char *buf, int cap, const char *key, int value);
int json_emit_kv_raw(char *buf, int cap, const char *key, const char *raw_json);

#endif
