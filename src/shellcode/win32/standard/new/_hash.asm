
;
; HASH - NASM macro for calculating win32 symbol hashes
; Usage: HASH instruction, 'SymbolName'
;
%ifnmacro HASH
%macro HASH 2
	%assign i 1			; i = 1
	%assign h 0			; h = 0
	%strlen len %2			; len = strlen(%2)
	%rep len
		%substr char %2 i	; fetch next character
		%assign h \
			(h<<0x13) + \
			(h>>0x0d) + \
			char		; rotate and add
		%assign i i+1		; increment i
	%endrep
	%1 h				; return instruction with hash
%endmacro
%endif

;
; Examples:
;
;
; [BITS 32]
;
; HASH push, 'LoadLibraryA'			; push dword 0xec0e4e8e
; HASH {mov eax,}, 'LoadLibraryA'		; mov eax,0xec0e4e8e
; HASH dd, 'LoadLibraryA'			; dd 0xec0e4e8e
; HASH dd, 'ExitProcess'			; dd 0x73e2d87e



