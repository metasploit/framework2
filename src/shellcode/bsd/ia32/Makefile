ASM=nasm
STAGERS=stager_sock_bind stager_sock_find stager_sock_reverse
STAGES=stage_tcp_shell
SINGLE=single_exec single_reverse_libinject single_findsock
OBJS=${STAGERS} ${STAGES} ${SINGLE}

include ../../Makefile.incl

all: 
	@for i in ${OBJS}; ${BUILDASMBSD}; done

clean:
	rm -f *.o *.hex ${OBJS} *.disasm
