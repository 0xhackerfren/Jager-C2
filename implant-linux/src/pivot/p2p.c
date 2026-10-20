/**
 * Linux P2P pivot - Unix domain socket listener + TCP relay
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../../include/pivot.h"
#include "../../include/json.h"

#define P2P_BUF       65536
#define MAX_P2P_CONN  8

typedef struct {
    int fd;
    int relay_fd;
    char target[256];
    int port;
    int active;
    pthread_t thread;
} P2P_CONN;

typedef struct {
    char id[64];
    char target[256];
    int port;
    char socket_path[108];
    int fd;
    int active;
} P2P_ROUTE;

static char g_sock_path[108] = "/tmp/jager-p2p.sock";
static int g_listen_fd = -1;
static volatile int g_listening = 0;
static pthread_t g_listen_thread;
static P2P_CONN g_conns[MAX_P2P_CONN];
static int g_tcp_listen_fd = -1;
static volatile int g_tcp_listening = 0;
static pthread_t g_tcp_thread;

static pthread_mutex_t g_p2p_lock = PTHREAD_MUTEX_INITIALIZER;
static char g_relay_host[256] = {0};
static int g_relay_port = 0;
static P2P_ROUTE g_routes[MAX_P2P_CONN];
static int g_route_count = 0;

static void relay_loop(int a, int b) {
    fd_set rfds;
    char buf[P2P_BUF];
    while (1) {
        FD_ZERO(&rfds);
        FD_SET(a, &rfds);
        FD_SET(b, &rfds);
        int mx = (a > b) ? a : b;
        if (select(mx + 1, &rfds, NULL, NULL, NULL) <= 0)
            break;

        if (FD_ISSET(a, &rfds)) {
            ssize_t n = read(a, buf, sizeof(buf));
            if (n <= 0)
                break;
            if (write(b, buf, (size_t)n) != n)
                break;
        }
        if (FD_ISSET(b, &rfds)) {
            ssize_t n = read(b, buf, sizeof(buf));
            if (n <= 0)
                break;
            if (write(a, buf, (size_t)n) != n)
                break;
        }
    }
}

static int connect_tcp_relay(const char *host, int port) {
    int peer = socket(AF_INET, SOCK_STREAM, 0);
    if (peer < 0)
        return -1;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        close(peer);
        return -1;
    }

    if (connect(peer, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(peer);
        return -1;
    }

    return peer;
}

static int alloc_conn_slot(void) {
    for (int i = 0; i < MAX_P2P_CONN; i++) {
        if (!g_conns[i].active)
            return i;
    }
    return -1;
}

static void *p2p_hold_thread(void *arg) {
    P2P_CONN *conn = (P2P_CONN *)arg;
    char buf[P2P_BUF];

    while (conn->active) {
        ssize_t n = read(conn->fd, buf, sizeof(buf));
        if (n <= 0)
            break;
    }

    if (conn->relay_fd >= 0)
        close(conn->relay_fd);
    if (conn->fd >= 0)
        close(conn->fd);
    conn->fd = -1;
    conn->relay_fd = -1;
    conn->active = 0;
    return NULL;
}

static void *p2p_client_thread(void *arg) {
    P2P_CONN *conn = (P2P_CONN *)arg;
    char host[256] = {0};
    int port = 0;

    pthread_mutex_lock(&g_p2p_lock);
    strncpy(host, g_relay_host, sizeof(host) - 1);
    port = g_relay_port;
    pthread_mutex_unlock(&g_p2p_lock);

    if (!host[0] || port <= 0) {
        close(conn->fd);
        conn->active = 0;
        return NULL;
    }

    int peer = connect_tcp_relay(host, port);
    if (peer < 0) {
        close(conn->fd);
        conn->active = 0;
        return NULL;
    }

    conn->relay_fd = peer;
    relay_loop(conn->fd, peer);
    conn->active = 0;
    return NULL;
}

static void *p2p_listen_thread(void *arg) {
    (void)arg;
    while (g_listening) {
        int client = accept(g_listen_fd, NULL, NULL);
        if (client < 0) {
            if (!g_listening)
                break;
            usleep(100000);
            continue;
        }

        int slot = alloc_conn_slot();
        if (slot < 0) {
            close(client);
            continue;
        }

        g_conns[slot].fd = client;
        g_conns[slot].relay_fd = -1;
        g_conns[slot].target[0] = '\0';
        g_conns[slot].port = 0;
        g_conns[slot].active = 1;
        pthread_create(&g_conns[slot].thread, NULL, p2p_client_thread, &g_conns[slot]);
        pthread_detach(g_conns[slot].thread);
    }
    return NULL;
}

static void *tcp_listen_thread(void *arg) {
    (void)arg;
    while (g_tcp_listening) {
        int client = accept(g_tcp_listen_fd, NULL, NULL);
        if (client < 0) {
            if (!g_tcp_listening)
                break;
            usleep(100000);
            continue;
        }

        int slot = alloc_conn_slot();
        if (slot < 0) {
            close(client);
            continue;
        }

        g_conns[slot].fd = client;
        g_conns[slot].relay_fd = -1;
        g_conns[slot].target[0] = '\0';
        g_conns[slot].port = 0;
        g_conns[slot].active = 1;
        pthread_create(&g_conns[slot].thread, NULL, p2p_client_thread, &g_conns[slot]);
        pthread_detach(g_conns[slot].thread);
    }
    return NULL;
}

static BOOL store_tcp_connection(const char *host, int port, int fd) {
    pthread_mutex_lock(&g_p2p_lock);
    strncpy(g_relay_host, host, sizeof(g_relay_host) - 1);
    g_relay_port = port;

    int slot = alloc_conn_slot();
    if (slot < 0) {
        pthread_mutex_unlock(&g_p2p_lock);
        return FALSE;
    }

    g_conns[slot].fd = fd;
    g_conns[slot].relay_fd = -1;
    strncpy(g_conns[slot].target, host, sizeof(g_conns[slot].target) - 1);
    g_conns[slot].port = port;
    g_conns[slot].active = 1;
    pthread_create(&g_conns[slot].thread, NULL, p2p_hold_thread, &g_conns[slot]);
    pthread_detach(g_conns[slot].thread);
    pthread_mutex_unlock(&g_p2p_lock);
    return TRUE;
}

BOOL p2p_listen(const char *socket_path) {
    if (g_listening)
        return TRUE;

    if (socket_path && socket_path[0])
        strncpy(g_sock_path, socket_path, sizeof(g_sock_path) - 1);

    unlink(g_sock_path);

    g_listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (g_listen_fd < 0)
        return FALSE;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, g_sock_path, sizeof(addr.sun_path) - 1);

    if (bind(g_listen_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(g_listen_fd);
        g_listen_fd = -1;
        return FALSE;
    }

    if (listen(g_listen_fd, MAX_P2P_CONN) != 0) {
        close(g_listen_fd);
        g_listen_fd = -1;
        return FALSE;
    }

    g_listening = 1;
    pthread_create(&g_listen_thread, NULL, p2p_listen_thread, NULL);
    pthread_detach(g_listen_thread);
    return TRUE;
}

BOOL p2p_connect(const char *target, const char *socket_path) {
    char path[108];
    if (socket_path && socket_path[0])
        strncpy(path, socket_path, sizeof(path) - 1);
    else
        snprintf(path, sizeof(path), "/tmp/jager-p2p.sock");

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return FALSE;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return FALSE;
    }

    pthread_mutex_lock(&g_p2p_lock);
    int slot = alloc_conn_slot();
    if (slot < 0) {
        pthread_mutex_unlock(&g_p2p_lock);
        close(fd);
        return FALSE;
    }

    g_conns[slot].fd = fd;
    g_conns[slot].relay_fd = -1;
    g_conns[slot].port = 0;
    if (target && target[0]) {
        strncpy(g_conns[slot].target, target, sizeof(g_conns[slot].target) - 1);
        strncpy(g_relay_host, target, sizeof(g_relay_host) - 1);
    }
    g_conns[slot].active = 1;
    pthread_create(&g_conns[slot].thread, NULL, p2p_hold_thread, &g_conns[slot]);
    pthread_detach(g_conns[slot].thread);
    pthread_mutex_unlock(&g_p2p_lock);
    return TRUE;
}

BOOL tcp_pivot_listen(int port) {
    if (g_tcp_listening)
        return TRUE;

    g_tcp_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (g_tcp_listen_fd < 0)
        return FALSE;

    int opt = 1;
    setsockopt(g_tcp_listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((uint16_t)port);

    if (bind(g_tcp_listen_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(g_tcp_listen_fd);
        g_tcp_listen_fd = -1;
        return FALSE;
    }

    if (listen(g_tcp_listen_fd, MAX_P2P_CONN) != 0) {
        close(g_tcp_listen_fd);
        g_tcp_listen_fd = -1;
        return FALSE;
    }

    g_tcp_listening = 1;
    pthread_create(&g_tcp_thread, NULL, tcp_listen_thread, NULL);
    pthread_detach(g_tcp_thread);
    return TRUE;
}

BOOL tcp_pivot_connect(const char *host, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return FALSE;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        close(fd);
        return FALSE;
    }

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return FALSE;
    }

    return store_tcp_connection(host, port, fd);
}

BOOL p2p_relay_configure(const char *json, size_t json_len) {
    if (!json || json_len < 3)
        return FALSE;

    char buf[4096];
    if (json_len >= sizeof(buf))
        return FALSE;
    memcpy(buf, json, json_len);
    buf[json_len] = '\0';

    const char *upstream = strstr(buf, "\"upstream\"");
    if (upstream) {
        char host[256] = {0};
        int port = 0;
        json_find_string(upstream, "host", host, sizeof(host));
        json_find_string(upstream, "target", host, sizeof(host));
        json_find_int(upstream, "port", &port);
        if (host[0] && port > 0) {
            pthread_mutex_lock(&g_p2p_lock);
            strncpy(g_relay_host, host, sizeof(g_relay_host) - 1);
            g_relay_port = port;
            pthread_mutex_unlock(&g_p2p_lock);
        }
    }

    const char *routes = strstr(buf, "\"routes\"");
    if (!routes)
        return TRUE;

    const char *p = routes;
    while ((p = strchr(p, '{')) != NULL) {
        const char *end = strchr(p, '}');
        if (!end)
            break;

        char obj[512];
        size_t olen = (size_t)(end - p + 1);
        if (olen >= sizeof(obj))
            break;
        memcpy(obj, p, olen);
        obj[olen] = '\0';

        char id[64] = {0};
        char target[256] = {0};
        char sock_path[108] = {0};
        int port = 0;
        json_find_string(obj, "id", id, sizeof(id));
        json_find_string(obj, "target", target, sizeof(target));
        json_find_string(obj, "socket_path", sock_path, sizeof(sock_path));
        json_find_string(obj, "pipe", sock_path, sizeof(sock_path));
        json_find_int(obj, "port", &port);

        if (!id[0] || !target[0])
            goto next_route;

        pthread_mutex_lock(&g_p2p_lock);
        if (g_route_count < MAX_P2P_CONN) {
            P2P_ROUTE *route = &g_routes[g_route_count++];
            memset(route, 0, sizeof(*route));
            strncpy(route->id, id, sizeof(route->id) - 1);
            strncpy(route->target, target, sizeof(route->target) - 1);
            route->port = port;
            if (sock_path[0])
                strncpy(route->socket_path, sock_path, sizeof(route->socket_path) - 1);

            if (port > 0) {
                route->fd = connect_tcp_relay(target, port);
                route->active = route->fd >= 0;
                if (route->active) {
                    strncpy(g_relay_host, target, sizeof(g_relay_host) - 1);
                    g_relay_port = port;
                }
            } else if (sock_path[0]) {
                char full_path[108];
                snprintf(full_path, sizeof(full_path), "/tmp/%s", sock_path);
                route->fd = socket(AF_UNIX, SOCK_STREAM, 0);
                if (route->fd >= 0) {
                    struct sockaddr_un uaddr;
                    memset(&uaddr, 0, sizeof(uaddr));
                    uaddr.sun_family = AF_UNIX;
                    strncpy(uaddr.sun_path, full_path, sizeof(uaddr.sun_path) - 1);
                    if (connect(route->fd, (struct sockaddr *)&uaddr, sizeof(uaddr)) != 0) {
                        close(route->fd);
                        route->fd = -1;
                        route->active = 0;
                    } else {
                        route->active = 1;
                    }
                }
            }
        }
        pthread_mutex_unlock(&g_p2p_lock);

    next_route:
        p = end + 1;
    }

    return TRUE;
}

void p2p_cleanup(void) {
    g_listening = 0;
    g_tcp_listening = 0;

    pthread_mutex_lock(&g_p2p_lock);
    for (int i = 0; i < MAX_P2P_CONN; i++) {
        if (g_conns[i].active) {
            g_conns[i].active = 0;
            if (g_conns[i].fd >= 0)
                close(g_conns[i].fd);
            if (g_conns[i].relay_fd >= 0)
                close(g_conns[i].relay_fd);
            g_conns[i].fd = -1;
            g_conns[i].relay_fd = -1;
        }
        if (g_routes[i].active && g_routes[i].fd >= 0) {
            close(g_routes[i].fd);
            g_routes[i].fd = -1;
            g_routes[i].active = 0;
        }
    }
    g_route_count = 0;
    pthread_mutex_unlock(&g_p2p_lock);

    if (g_listen_fd >= 0) {
        close(g_listen_fd);
        g_listen_fd = -1;
    }
    if (g_tcp_listen_fd >= 0) {
        close(g_tcp_listen_fd);
        g_tcp_listen_fd = -1;
    }
    unlink(g_sock_path);
}
