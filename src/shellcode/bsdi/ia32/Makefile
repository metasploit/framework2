NASM=nasm
STAGERS=stager_sock_bind stager_sock_find stager_sock_reverse 
OBJS=${STAGERS} ${PROVIDERS}

include ../../Makefile.incl

all: 
	@for i in ${OBJS}; ${BUILDASM}; done

clean:
	rm -f *.o *.hex ${OBJS} *.disasm
