/**
 * portfwd.c - TCP port forwarding for Linux
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <netdb.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../../include/pivot.h"

#define MAX_FORWARDS     16
#define PORTFWD_BUF_SIZE 65536

typedef struct {
    int id;
    int active;
    char bind_addr[64];
    int bind_port;
    char fwd_addr[256];
    int fwd_port;
    int listen_fd;
    pthread_t thread;
    int conn_count;
} PORTFWD;

static PORTFWD g_forwards[MAX_FORWARDS];
static pthread_mutex_t g_portfwd_lock = PTHREAD_MUTEX_INITIALIZER;
static int g_portfwd_init = 0;
static int g_next_id = 1;

static void portfwd_module_init(void) {
    if (g_portfwd_init) return;
    memset(g_forwards, 0, sizeof(g_forwards));
    g_portfwd_init = 1;
}

static PORTFWD *find_free_slot(void) {
    for (int i = 0; i < MAX_FORWARDS; i++) {
        if (!g_forwards[i].active) return &g_forwards[i];
    }
    return NULL;
}

static void relay_sockets(int a, int b);

static void *relay_thread(void *arg) {
    int *pair = (int *)arg;
    int a = pair[0];
    int b = pair[1];
    free(pair);
    relay_sockets(a, b);
    return NULL;
}

static void relay_sockets(int a, int b) {
    fd_set rfds;
    char buf[PORTFWD_BUF_SIZE];
    struct timeval tv;

    while (1) {
        FD_ZERO(&rfds);
        FD_SET(a, &rfds);
        FD_SET(b, &rfds);
        int mx = (a > b) ? a : b;

        tv.tv_sec = 1;
        tv.tv_usec = 0;
        if (select(mx + 1, &rfds, NULL, NULL, &tv) <= 0) continue;

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

static int connect_remote(const char *host, int port) {
    struct addrinfo hints, *res = NULL, *rp;
    char port_str[16];

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    snprintf(port_str, sizeof(port_str), "%d", port);
    if (getaddrinfo(host, port_str, &hints, &res) != 0) return -1;

    int sock = -1;
    for (rp = res; rp; rp = rp->ai_next) {
        sock = (int)socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock < 0) continue;
        if (connect(sock, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(sock);
        sock = -1;
    }
    freeaddrinfo(res);
    return sock;
}

static void *local_fwd_thread(void *arg) {
    PORTFWD *entry = (PORTFWD *)arg;

    while (entry->active) {
        struct sockaddr_in cli;
        socklen_t clen = sizeof(cli);
        int client = accept(entry->listen_fd, (struct sockaddr *)&cli, &clen);
        if (client < 0) {
            if (!entry->active) break;
            continue;
        }

        int fwd_sock = connect_remote(entry->fwd_addr, entry->fwd_port);
        if (fwd_sock < 0) {
            close(client);
            continue;
        }

        pthread_t relay_tid;
        int *pair = (int *)malloc(sizeof(int) * 2);
        if (!pair) {
            close(fwd_sock);
            close(client);
            continue;
        }
        pair[0] = client;
        pair[1] = fwd_sock;
        pthread_create(&relay_tid, NULL, relay_thread, pair);
        pthread_detach(relay_tid);
        __atomic_add_fetch(&entry->conn_count, 1, __ATOMIC_SEQ_CST);
    }

    if (entry->listen_fd >= 0) {
        close(entry->listen_fd);
        entry->listen_fd = -1;
    }
    return NULL;
}

static int portfwd_add_internal(const char *bind_addr, int bind_port,
                                const char *fwd_addr, int fwd_port) {
    if (!fwd_addr || bind_port <= 0 || fwd_port <= 0) return -1;

    portfwd_module_init();

    pthread_mutex_lock(&g_portfwd_lock);
    PORTFWD *entry = find_free_slot();
    if (!entry) {
        pthread_mutex_unlock(&g_portfwd_lock);
        return -1;
    }

    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        pthread_mutex_unlock(&g_portfwd_lock);
        return -1;
    }

    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)bind_port);
    if (bind_addr && bind_addr[0]) {
        if (inet_pton(AF_INET, bind_addr, &addr.sin_addr) <= 0) {
            close(listen_fd);
            pthread_mutex_unlock(&g_portfwd_lock);
            return -1;
        }
    } else {
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    }

    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(listen_fd);
        pthread_mutex_unlock(&g_portfwd_lock);
        return -1;
    }
    if (listen(listen_fd, 8) < 0) {
        close(listen_fd);
        pthread_mutex_unlock(&g_portfwd_lock);
        return -1;
    }

    entry->id = g_next_id++;
    entry->active = 1;
    entry->bind_port = bind_port;
    entry->fwd_port = fwd_port;
    entry->listen_fd = listen_fd;
    entry->conn_count = 0;
    strncpy(entry->bind_addr, (bind_addr && bind_addr[0]) ? bind_addr : "127.0.0.1",
            sizeof(entry->bind_addr) - 1);
    strncpy(entry->fwd_addr, fwd_addr, sizeof(entry->fwd_addr) - 1);

    pthread_create(&entry->thread, NULL, local_fwd_thread, entry);
    pthread_detach(entry->thread);

    int id = entry->id;
    pthread_mutex_unlock(&g_portfwd_lock);
    return id;
}

BOOL portfwd_add(int local_port, const char *remote_host, int remote_port, int *out_id) {
    int id = portfwd_add_internal("127.0.0.1", local_port, remote_host, remote_port);
    if (id < 0) return FALSE;
    if (out_id) *out_id = id;
    return TRUE;
}

BOOL portfwd_remove(int fwd_id) {
    portfwd_module_init();

    pthread_mutex_lock(&g_portfwd_lock);
    for (int i = 0; i < MAX_FORWARDS; i++) {
        if (g_forwards[i].active && g_forwards[i].id == fwd_id) {
            g_forwards[i].active = 0;
            if (g_forwards[i].listen_fd >= 0) {
                close(g_forwards[i].listen_fd);
                g_forwards[i].listen_fd = -1;
            }
            pthread_mutex_unlock(&g_portfwd_lock);
            return TRUE;
        }
    }
    pthread_mutex_unlock(&g_portfwd_lock);
    return FALSE;
}

int portfwd_list(char *out, int max_out) {
    if (!out || max_out <= 0) return -1;

    portfwd_module_init();

    int n, offset = 0;
    n = snprintf(out, (size_t)max_out,
                 "ID  | Bind            | Forward          | Conns\n");
    if (n > 0 && n < max_out) offset = n;
    n = snprintf(out + offset, (size_t)max_out - (size_t)offset,
                 "----|-----------------|------------------|------\n");
    if (n > 0 && offset + n < max_out) offset += n;

    pthread_mutex_lock(&g_portfwd_lock);
    for (int i = 0; i < MAX_FORWARDS; i++) {
        if (!g_forwards[i].active) continue;
        PORTFWD *e = &g_forwards[i];
        n = snprintf(out + offset, (size_t)max_out - (size_t)offset,
                     "%-3d | %s:%-5d | %s:%-5d | %d\n",
                     e->id, e->bind_addr, e->bind_port,
                     e->fwd_addr, e->fwd_port, e->conn_count);
        if (n > 0 && offset + n < max_out) offset += n; else break;
    }
    pthread_mutex_unlock(&g_portfwd_lock);
    return 0;
}

void portfwd_cleanup(void) {
    portfwd_module_init();

    pthread_mutex_lock(&g_portfwd_lock);
    for (int i = 0; i < MAX_FORWARDS; i++) {
        if (!g_forwards[i].active) continue;
        g_forwards[i].active = 0;
        if (g_forwards[i].listen_fd >= 0) {
            close(g_forwards[i].listen_fd);
            g_forwards[i].listen_fd = -1;
        }
    }
    pthread_mutex_unlock(&g_portfwd_lock);
}
