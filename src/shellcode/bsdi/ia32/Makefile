ASM=nasm
STAGERS=stager_sock_bind stager_sock_find stager_sock_reverse 
STAGES=stage_tcp_shell
SINGLE=
OBJS=${STAGERS} ${STAGES} ${SINGLE}

include ../../Makefile.incl

all: 
	@for i in ${OBJS}; ${BUILDASM}; done

clean:
	rm -f *.o *.hex ${OBJS} *.disasm
