# x64 return-address stack spoofing (MinGW AT&T syntax).
    .data
    .align 8
saved_ret:
    .quad 0
fake_ret_addr:
    .quad 0

    .text
    .globl spoof_set_fake_ret
spoof_set_fake_ret:
    movq %rcx, fake_ret_addr(%rip)
    ret

# rcx = target function pointer (Windows x64 first arg)
    .globl spoof_call
spoof_call:
    pop %r11
    pushq fake_ret_addr(%rip)
    movq %r11, saved_ret(%rip)
    jmp *%rcx

    .globl spoof_return
spoof_return:
    movq saved_ret(%rip), %r11
    pushq %r11
    ret

# Legacy entry — use spoof_call(target) from C instead.
    .globl spoof_call_stack
spoof_call_stack:
    ret
