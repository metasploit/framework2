;;
;
;
;
;
;;
BITS   32
GLOBAL _start

%include "generic.asm"

_start:
	execve_binsh EXECUTE_REDIRECT_IO | EXECUTE_DISABLE_READLINE
