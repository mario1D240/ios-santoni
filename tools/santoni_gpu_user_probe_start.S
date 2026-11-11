/* Internal ELF/AAPCS64 calls; only SVC crosses into Darwin. No libc ABI. */
.text
.global _start
.type _start,%function
_start:
    mov x9, sp
    ldr x0, [x9]
    add x1, x9, #8
    and x9, x9, #~15
    mov sp, x9
    bl sgpu_user_probe_entry
    mov x16, #1
    svc #0x80
1:  wfe
    b 1b
.size _start, .-_start

.global sgpu_syscall
.type sgpu_syscall,%function
sgpu_syscall:
    stp x19, x20, [sp, #-32]!
    str x30, [sp, #16]
    mov x19, x7
    mov x20, x0
    mov x16, x0
    mov x0, x1
    mov x1, x2
    mov x2, x3
    mov x3, x4
    mov x4, x5
    mov x5, x6
    svc #0x80
    cset w8, cs
    str w8, [x19]
    cbnz w8, 2f
    /* XNU fork returns its child discriminator in the second result register.
     * kern_fork.c labels retval[1]=0 for parent; child receives a nonzero flag.
     */
    cmp x20, #2
    b.ne 2f
    cmp x1, #0
    csel x0, xzr, x0, ne
2:  ldr x30, [sp, #16]
    ldp x19, x20, [sp], #32
    ret
.size sgpu_syscall, .-sgpu_syscall
