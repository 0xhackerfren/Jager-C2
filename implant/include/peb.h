#ifndef JAGER_PEB_H
#define JAGER_PEB_H

#include <windows.h>

/* Minimal PEB/LDR structures for ntdll base resolution (MinGW-safe). */

typedef struct _JAGER_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} JAGER_UNICODE_STRING, *PJAGER_UNICODE_STRING;

typedef struct _JAGER_LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    JAGER_UNICODE_STRING FullDllName;
    JAGER_UNICODE_STRING BaseDllName;
} JAGER_LDR_DATA_TABLE_ENTRY, *PJAGER_LDR_DATA_TABLE_ENTRY;

typedef struct _JAGER_PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} JAGER_PEB_LDR_DATA, *PJAGER_PEB_LDR_DATA;

typedef struct _JAGER_PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PJAGER_PEB_LDR_DATA Ldr;
} JAGER_PEB, *PJAGER_PEB;

#ifdef _WIN64
static __inline PJAGER_PEB jager_read_peb(void) {
    return (PJAGER_PEB)(ULONG_PTR)__readgsqword(0x60);
}
#else
static __inline PJAGER_PEB jager_read_peb(void) {
    return (PJAGER_PEB)(ULONG_PTR)__readfsdword(0x30);
}
#endif

#endif /* JAGER_PEB_H */
