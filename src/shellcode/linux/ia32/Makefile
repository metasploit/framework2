NASM=nasm
STAGERS=stager_sock_bind stager_egghunt stager_sock_find stager_sock_reverse 
STAGES=stage_tcp_shell stage_udp_shell
OBJS=${STAGERS} ${STAGES}

include ../../Makefile.incl

all: 
	@for i in ${OBJS}; ${BUILDASM}; done

clean:
	rm -f *.o *.hex ${OBJS} *.disasm
