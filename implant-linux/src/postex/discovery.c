/**
 * Linux system discovery
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <dirent.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../../include/postex.h"

int disc_interfaces(char *out, size_t cap) {
    struct ifaddrs *ifap = NULL, *ifa;
    size_t offset = 0;

    if (getifaddrs(&ifap) != 0) {
        snprintf(out, cap, "getifaddrs failed\n");
        return -1;
    }

    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) continue;
        if (ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)ifa->ifa_addr;
            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip));
            int n = snprintf(out + offset, cap - offset, "%s: %s\n", ifa->ifa_name, ip);
            if (n > 0 && offset + (size_t)n < cap) offset += (size_t)n; else break;
        } else if (ifa->ifa_addr->sa_family == AF_INET6) {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;
            char ip[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &sin6->sin6_addr, ip, sizeof(ip));
            int n = snprintf(out + offset, cap - offset, "%s: %s\n", ifa->ifa_name, ip);
            if (n > 0 && offset + (size_t)n < cap) offset += (size_t)n; else break;
        }
    }
    freeifaddrs(ifap);
    return 0;
}

static void parse_proc_net(const char *path, const char *proto, char *out, size_t cap, size_t *off) {
    FILE *f = fopen(path, "r");
    if (!f) return;
    char line[512];
    fgets(line, sizeof(line), f); /* skip header */
    while (fgets(line, sizeof(line), f) && *off < cap - 128) {
        unsigned long local_addr, rem_addr;
        unsigned int local_port, rem_port, state;
        if (sscanf(line, " %*d: %lx:%x %lx:%x %x",
                   &local_addr, &local_port, &rem_addr, &rem_port, &state) >= 5) {
            struct in_addr la, ra;
            la.s_addr = htonl((uint32_t)local_addr);
            ra.s_addr = htonl((uint32_t)rem_addr);
            char lip[32], rip[32];
            inet_ntop(AF_INET, &la, lip, sizeof(lip));
            inet_ntop(AF_INET, &ra, rip, sizeof(rip));
            int n = snprintf(out + *off, cap - *off, "%s %s:%u -> %s:%u state=%u\n",
                             proto, lip, local_port, rip, rem_port, state);
            if (n > 0 && *off + (size_t)n < cap) *off += (size_t)n; else break;
        }
    }
    fclose(f);
}

int disc_connections(char *out, size_t cap) {
    size_t offset = 0;
    parse_proc_net("/proc/net/tcp", "tcp", out, cap, &offset);
    parse_proc_net("/proc/net/udp", "udp", out, cap, &offset);
    parse_proc_net("/proc/net/tcp6", "tcp6", out, cap, &offset);
    return 0;
}

int disc_processes(char *out, size_t cap) {
    size_t offset = 0;
    DIR *d = opendir("/proc");
    if (!d) return -1;

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] < '0' || ent->d_name[0] > '9') continue;

        char cmdpath[64], statpath[64], exepath[64];
        snprintf(cmdpath, sizeof(cmdpath), "/proc/%s/cmdline", ent->d_name);
        snprintf(statpath, sizeof(statpath), "/proc/%s/status", ent->d_name);
        snprintf(exepath, sizeof(exepath), "/proc/%s/exe", ent->d_name);

        char cmdline[256] = {0};
        FILE *cf = fopen(cmdpath, "r");
        if (cf) {
            fread(cmdline, 1, sizeof(cmdline) - 1, cf);
            fclose(cf);
            for (char *p = cmdline; *p; p++)
                if (*p == '\0') *p = ' ';
        }

        char exe[256] = {0};
        ssize_t elen = readlink(exepath, exe, sizeof(exe) - 1);
        if (elen > 0) exe[elen] = '\0';

        offset += snprintf(out + offset, cap - offset, "PID %s  exe=%s  cmd=%s\n",
                           ent->d_name, exe[0] ? exe : "?", cmdline);
        if (offset >= cap - 256) break;
    }
    closedir(d);
    return 0;
}

int disc_users(char *out, size_t cap) {
    size_t offset = 0;
    FILE *f = fopen("/etc/passwd", "r");
    if (!f) return -1;

    char line[512];
    while (fgets(line, sizeof(line), f) && offset < cap - 512) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        offset += snprintf(out + offset, cap - offset, "%s\n", line);
    }
    fclose(f);

    if (access("/var/log/wtmp", R_OK) == 0)
        offset += snprintf(out + offset, cap - offset, "[+] wtmp present\n");

    return 0;
}
