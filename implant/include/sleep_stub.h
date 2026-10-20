#ifndef JAGER_SLEEP_STUB_H
#define JAGER_SLEEP_STUB_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
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

void __stdcall sleep_wake_decrypt(SleepStubContext *ctx);
void __stdcall sleep_pre_encrypt(SleepStubContext *ctx);
void __stdcall sleep_wake_signal(SleepWakeSignalCtx *ctx);

void CALLBACK sleep_ekko_timer_wake(PVOID param, BOOLEAN timer_or_wait_fired);
void CALLBACK sleep_zilean_timer_apc(PVOID param, DWORD timer_low, DWORD timer_high);
void CALLBACK sleep_tp_timer_wake(PTP_CALLBACK_INSTANCE inst, PVOID ctx, PTP_TIMER timer);

LONG WINAPI sleep_hwbp_veh_handler(EXCEPTION_POINTERS *ep);
void sleep_hwbp_stub_bind(SleepStubContext *crypt,
                          volatile LONG *toggle_count,
                          volatile LONG *encrypted_flag);

int sleep_stub_self_test(void);

#ifdef __cplusplus
}
#endif

#endif /* JAGER_SLEEP_STUB_H */
