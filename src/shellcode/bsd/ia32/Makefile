NASM=nasm
STAGERS=stager_sock_bind stager_sock_find stager_sock_reverse
STAGES=
SINGLE=single_exec
OBJS=${STAGERS} ${STAGES} ${SINGLE}

include ../../Makefile.incl

all: 
	@for i in ${OBJS}; ${BUILDASMBSD}; done

clean:
	rm -f *.o *.hex ${OBJS} *.disasm
