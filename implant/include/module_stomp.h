#ifndef JAGER_MODULE_STOMP_H
#define JAGER_MODULE_STOMP_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Load a DLL into a remote process via LdrLoadDll (avoids LoadLibrary ETW). */
BOOL remote_load_dll(HANDLE proc, const wchar_t *dll_path, HMODULE *out_mod);

/* Resolve a module already mapped in the remote process by base name. */
BOOL remote_find_module(HANDLE proc, const char *module_name, HMODULE *out_mod);

/* Locate the first executable section (.text) of a remote PE module. */
BOOL find_remote_text_section(HANDLE proc, HMODULE mod, PVOID *text_addr, DWORD *text_size);

/* RW -> write -> RX over a remote executable section. */
BOOL stomp_text_section(HANDLE proc, PVOID text_addr, DWORD text_size,
                        const BYTE *data, DWORD data_size);

/* Build a full path for a System32 DLL name (e.g. "amsi.dll"). */
BOOL module_stomp_system32_path(const char *dll_name, wchar_t *out, DWORD out_chars);

#ifdef __cplusplus
}
#endif

#endif /* JAGER_MODULE_STOMP_H */
