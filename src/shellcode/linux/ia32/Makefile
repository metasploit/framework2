NASM=nasm
STAGERS=stager_sock_bind stager_egghunt stager_sock_find stager_sock_reverse 
PROVIDERS=provider_tcp_shell provider_udp_shell
OBJS=${STAGERS} ${PROVIDERS}

all: 
	@for i in ${OBJS}; do echo -n "Building $$i..." && nasm -f bin $$i.asm -o $$i.o && nasm -f elf $$i.asm -o $$i.o.tmp && ld $$i.o.tmp -o $$i && rm -f $$i.o.tmp && xxd -c 16 -ps $$i.o | sed 's/\([0123456789abcdef][0123456789abcdef]\)/\\x\1/g' > $$i.hex && wc -c $$i.o | cut -f 6 -d' '; ndisasm -b 32 $$i.o > $$i.disasm; done

clean:
	rm -f *.o *.hex ${OBJS} *.disasm
