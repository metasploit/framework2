NASM=nasm
OBJS=stager_sock_reverse

all: 
	@for i in ${OBJS}; do echo -n "Building $$i..."; nasm -f bin $$i.asm -o $$i.o; nasm -f elf $$i.asm -o $$i.o.tmp; ld $$i.o.tmp -o $$i; rm -f $$i.o.tmp; wc -c $$i.o | cut -f 6 -d' '; done

clean:
	rm -f *.o ${OBJS}
