/**
 * transport_failover.c - C2 URL failover with rotation on consecutive failures
 */
#include <windows.h>
#include <stdio.h>
#include "../../include/transport.h"

static void trim(char *s) {
    if (!s) return;
    while (*s == ' ' || *s == '\t') {
        memmove(s, s + 1, lstrlenA(s));
    }
    DWORD len = (DWORD)lstrlenA(s);
    while (len > 0 && (s[len - 1] == ' ' || s[len - 1] == '\t' || s[len - 1] == ','))
        s[--len] = '\0';
}

void failover_init(C2_FAILOVER *fo, const char *url_list) {
    if (!fo) return;
    ZeroMemory(fo, sizeof(C2_FAILOVER));
    fo->max_fails = 3;
    fo->current = 0;
    fo->fail_count = 0;

    if (!url_list || !url_list[0]) return;

    char buf[4096];
    lstrcpynA(buf, url_list, sizeof(buf));

    char *ctx = NULL;
    char *tok = strtok_s(buf, ",", &ctx);
    while (tok && fo->count < MAX_C2_URLS) {
        trim(tok);
        if (tok[0]) {
            lstrcpynA(fo->urls[fo->count], tok, sizeof(fo->urls[0]));
            fo->count++;
        }
        tok = strtok_s(NULL, ",", &ctx);
    }
}

const char *failover_get_url(C2_FAILOVER *fo) {
    if (!fo || fo->count == 0) return NULL;
    if (fo->current >= fo->count) fo->current = 0;
    return fo->urls[fo->current];
}

void failover_mark_success(C2_FAILOVER *fo) {
    if (!fo) return;
    fo->fail_count = 0;
}

void failover_mark_failure(C2_FAILOVER *fo) {
    if (!fo || fo->count <= 1) return;
    fo->fail_count++;
    if (fo->fail_count >= fo->max_fails) {
        fo->fail_count = 0;
        fo->current = (fo->current + 1) % fo->count;
    }
}
