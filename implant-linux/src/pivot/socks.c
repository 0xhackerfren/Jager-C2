/**
 * Linux SOCKS5 proxy
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <netdb.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../../include/pivot.h"

#define SOCKS5_VERSION       0x05
#define SOCKS5_AUTH_NONE     0x00
#define SOCKS5_CMD_CONNECT   0x01
#define SOCKS5_ATYP_IPV4     0x01
#define SOCKS5_ATYP_DOMAIN   0x03
#define SOCKS5_REP_SUCCESS   0x00
#define SOCKS5_REP_FAILURE   0x01

static int g_listen_fd = -1;
static int g_socks_port = 0;
static pthread_mutex_t g_socks_lock = PTHREAD_MUTEX_INITIALIZER;
static volatile int g_socks_running = 0;
static pthread_t g_socks_thread;

static void relay_sockets(int a, int b) {
    fd_set rfds;
    char buf[8192];
    while (1) {
        FD_ZERO(&rfds);
        FD_SET(a, &rfds);
        FD_SET(b, &rfds);
        int mx = (a > b) ? a : b;
        if (select(mx + 1, &rfds, NULL, NULL, NULL) <= 0) break;

        if (FD_ISSET(a, &rfds)) {
            ssize_t n = read(a, buf, sizeof(buf));
            if (n <= 0) break;
            if (write(b, buf, (size_t)n) != n) break;
        }
        if (FD_ISSET(b, &rfds)) {
            ssize_t n = read(b, buf, sizeof(buf));
            if (n <= 0) break;
            if (write(a, buf, (size_t)n) != n) break;
        }
    }
    close(a);
    close(b);
}

static void *socks_client_thread(void *arg) {
    int client = (int)(intptr_t)arg;
    unsigned char buf[512];
    ssize_t n = recv(client, buf, sizeof(buf), 0);
    if (n < 3 || buf[0] != SOCKS5_VERSION) { close(client); return NULL; }

    unsigned char resp[2] = {SOCKS5_VERSION, SOCKS5_AUTH_NONE};
    send(client, resp, 2, 0);

    n = recv(client, buf, sizeof(buf), 0);
    if (n < 7 || buf[0] != SOCKS5_VERSION || buf[1] != SOCKS5_CMD_CONNECT) {
        close(client);
        return NULL;
    }

    char host[256] = {0};
    int port = 0;

    if (buf[3] == SOCKS5_ATYP_IPV4) {
        snprintf(host, sizeof(host), "%u.%u.%u.%u",
                 buf[4], buf[5], buf[6], buf[7]);
        port = (buf[8] << 8) | buf[9];
    } else if (buf[3] == SOCKS5_ATYP_DOMAIN) {
        int hlen = buf[4];
        if (n < 5 + hlen + 2) {
            close(client);
            return NULL; /* Not enough data */
        }
        if (hlen >= (int)sizeof(host)) hlen = (int)sizeof(host) - 1;
        memcpy(host, &buf[5], (size_t)hlen);
        host[hlen] = '\0';
        port = (buf[5 + hlen] << 8) | buf[6 + hlen];
    } else {
        close(client);
        return NULL;
    }

    int remote = socket(AF_INET, SOCK_STREAM, 0);
    if (remote < 0) { close(client); return NULL; }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {
        struct hostent *he = gethostbyname(host);
        if (!he) {
            unsigned char fail[10] = {5, SOCKS5_REP_FAILURE, 0, 1, 0, 0, 0, 0, 0, 0};
            send(client, fail, 10, 0);
            close(remote);
            close(client);
            return NULL;
        }
        memcpy(&addr.sin_addr, he->h_addr, (size_t)he->h_length);
    }

    if (connect(remote, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        unsigned char fail[10] = {5, SOCKS5_REP_FAILURE, 0, 1, 0, 0, 0, 0, 0, 0};
        send(client, fail, 10, 0);
        close(remote);
        close(client);
        return NULL;
    }

    unsigned char ok[10] = {5, SOCKS5_REP_SUCCESS, 0, 1, 0, 0, 0, 0, 0, 0};
    send(client, ok, 10, 0);
    relay_sockets(client, remote);
    return NULL;
}

static void *socks_accept_loop(void *arg) {
    (void)arg;
    while (1) {
        int listen_fd;
        int running;

        pthread_mutex_lock(&g_socks_lock);
        running = g_socks_running;
        listen_fd = g_listen_fd;
        pthread_mutex_unlock(&g_socks_lock);

        if (!running || listen_fd < 0)
            break;

        struct sockaddr_in cli;
        socklen_t clen = sizeof(cli);
        int client = accept(listen_fd, (struct sockaddr *)&cli, &clen);
        if (client < 0) {
            pthread_mutex_lock(&g_socks_lock);
            running = g_socks_running;
            pthread_mutex_unlock(&g_socks_lock);
            if (!running)
                break;
            continue;
        }

        pthread_t tid;
        pthread_create(&tid, NULL, socks_client_thread, (void *)(intptr_t)client);
        pthread_detach(tid);
    }
    return NULL;
}

BOOL socks_start(int port) {
    pthread_mutex_lock(&g_socks_lock);
    if (g_socks_running) {
        pthread_mutex_unlock(&g_socks_lock);
        return FALSE;
    }
    pthread_mutex_unlock(&g_socks_lock);
    if (!port) port = 1080;

    g_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (g_listen_fd < 0) return FALSE;

    int opt = 1;
    setsockopt(g_listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((uint16_t)port);

    if (bind(g_listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(g_listen_fd);
        g_listen_fd = -1;
        return FALSE;
    }
    if (listen(g_listen_fd, 16) < 0) {
        close(g_listen_fd);
        g_listen_fd = -1;
        return FALSE;
    }

    g_socks_port = port;
    pthread_mutex_lock(&g_socks_lock);
    g_socks_running = 1;
    pthread_mutex_unlock(&g_socks_lock);
    pthread_create(&g_socks_thread, NULL, socks_accept_loop, NULL);
    return TRUE;
}

BOOL socks_stop(void) {
    pthread_mutex_lock(&g_socks_lock);
    if (!g_socks_running) {
        pthread_mutex_unlock(&g_socks_lock);
        return FALSE;
    }
    g_socks_running = 0;
    if (g_listen_fd >= 0) {
        shutdown(g_listen_fd, SHUT_RDWR);
        close(g_listen_fd);
        g_listen_fd = -1;
    }
    pthread_mutex_unlock(&g_socks_lock);
    return TRUE;
}

void pivot_cleanup(void) {
    tunnel_cleanup();
    portfwd_cleanup();
    socks_stop();
}
