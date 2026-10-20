/**
 * Linux anti-analysis: ptrace, /proc, eBPF detection
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <dirent.h>
#include "../../include/evasion.h"

int check_ptrace(void) {
    /*
     * Fork-based ptrace check: child attempts PTRACE_TRACEME.
     * Avoids breaking the parent after daemonize()/setsid().
     */
    pid_t child = fork();
    if (child < 0) return 0;
    if (child == 0) {
        _exit(ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0 ? 1 : 0);
    }
    int status = 0;
    waitpid(child, &status, 0);
    return WIFEXITED(status) && WEXITSTATUS(status) != 0;
}

int check_proc_status(void) {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return 0;

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            int pid = atoi(line + 10);
            fclose(f);
            return pid != 0;
        }
    }
    fclose(f);
    return 0;
}

int check_ebpf_tracing(void) {
    /* Check /sys/fs/bpf for programs (heuristic) */
    DIR *d = opendir("/sys/fs/bpf");
    if (d) {
        struct dirent *ent;
        int count = 0;
        while ((ent = readdir(d)) != NULL) {
            if (ent->d_name[0] != '.') count++;
        }
        closedir(d);
        if (count > 10) return 1;
    }

    /* Scan fdinfo for bpf program references */
    char fdpath[64];
    snprintf(fdpath, sizeof(fdpath), "/proc/self/fdinfo");
    d = opendir(fdpath);
    if (d) {
        struct dirent *ent;
        while ((ent = readdir(d)) != NULL) {
            if (ent->d_name[0] == '.') continue;
            char info[128];
            snprintf(info, sizeof(info), "/proc/self/fdinfo/%s", ent->d_name);
            FILE *f = fopen(info, "r");
            if (!f) continue;
            char line[256];
            while (fgets(line, sizeof(line), f)) {
                if (strstr(line, "bpf-prog") || strstr(line, "bpf-map")) {
                    fclose(f);
                    closedir(d);
                    return 1;
                }
            }
            fclose(f);
        }
        closedir(d);
    }
    return 0;
}

int check_sandbox(void) {
    if (access("/.dockerenv", F_OK) == 0) return 1;
    if (access("/proc/vz", F_OK) == 0) return 1;

    FILE *f = fopen("/proc/1/cgroup", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, "docker") || strstr(line, "lxc") || strstr(line, "kubepods")) {
                fclose(f);
                return 1;
            }
        }
        fclose(f);
    }
    return 0;
}

int anti_analysis_gate(void) {
    if (check_sandbox()) return 1;
    if (check_ptrace()) return 1;
    if (check_proc_status()) return 1;
    if (check_ebpf_tracing()) return 1;
    return 0;
}
