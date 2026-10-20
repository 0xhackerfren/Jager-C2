/**
 * transport_front.c - Domain fronting for HTTPS transport
 */
#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include "../../include/transport.h"

BOOL domain_front_init(DOMAIN_FRONT_CONFIG *cfg, const char *cdn_host, const char *actual_host) {
    if (!cfg) return FALSE;
    ZeroMemory(cfg, sizeof(DOMAIN_FRONT_CONFIG));
    if (!cdn_host || !actual_host || !cdn_host[0] || !actual_host[0])
        return FALSE;

    lstrcpynA(cfg->cdn_host, cdn_host, sizeof(cfg->cdn_host));
    lstrcpynA(cfg->actual_host, actual_host, sizeof(cfg->actual_host));
    cfg->enabled = TRUE;
    return TRUE;
}

BOOL domain_front_apply(HINTERNET hRequest, DOMAIN_FRONT_CONFIG *cfg) {
    if (!hRequest || !cfg || !cfg->enabled) return FALSE;

    wchar_t wHost[256];
    MultiByteToWideChar(CP_UTF8, 0, cfg->actual_host, -1, wHost, 256);

    wchar_t hdr[320];
    swprintf(hdr, 320, L"Host: %s\r\n", wHost);
    return WinHttpAddRequestHeaders(hRequest, hdr, (DWORD)-1L,
                                    WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
}

const char *domain_front_connect_host(DOMAIN_FRONT_CONFIG *cfg, const char *url_host) {
    if (cfg && cfg->enabled && cfg->cdn_host[0])
        return cfg->cdn_host;
    return url_host;
}
