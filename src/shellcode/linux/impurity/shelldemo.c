/*
 * Copyright (c) 2004-2005 vlad902 <vlad902 [at] gmail.com>
 * This file is part of the Metasploit Framework.
 * $Revision$
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>
#ifdef SYSCALL_REBOOT
#include <linux/reboot.h>
#else
#include <sys/reboot.h>
#endif

#define	MIN(a, b)		((a) < (b) ? (a) : (b))

void parse(char *, int *, char * []);


/* Base */
void cmd_help(int, char * []);
void cmd_exec(int, char * []);
void cmd_quit(int, char * []);

/* File structure */
/* XXX: chown, chmod, rename, move, stat, symlink, link, ls */
void cmd_close(int, char * []);
void cmd_open(int, char * []);
void cmd_lseek(int, char * []);
void cmd_read(int, char * []);
void cmd_write(int, char * []);
void cmd_unlink(int, char * []);

/* Directory structure */
void cmd_getcwd(int, char * []);
void cmd_chdir(int, char * []);
void cmd_mkdir(int, char * []);
void cmd_rmdir(int, char * []);

/* Privilges */
void cmd_getid(int, char * []);
void cmd_setuid(int, char * []);
void cmd_setgid(int, char * []);

/* Process */
/* XXX: kill, ps */

/* Enviorment */
/* XXX: setenv, getenv, showenv */

/* System */
void cmd_hostname(int, char * []);
void cmd_reboot(int, char * []);
void cmd_shutdown(int, char * []);
void cmd_halt(int, char * []);

/* Misc. */
void cmd_lsfd(int, char * []);

struct __cmdhandler
{
	char * cmd;
	void (* handler)(int, char * []);
	unsigned int arg_min;
	unsigned int arg_max;
};

struct __cmdhandler handlerlist[] =
{
	{ "help", &cmd_help, 0, 0 },
	{ "exec", &cmd_exec, 1, 1 },
	{ "quit", &cmd_quit, 0, 0 },
	{ "exit", &cmd_quit, 0, 0 },

	{ "open", &cmd_open, 1, 1 },
	{ "lseek", &cmd_lseek, 3, 3 },
	{ "read", &cmd_read, 1, 2 },
	{ "write", &cmd_write, 2, 2 },
	{ "close", &cmd_close, 1, 1 },
	{ "unlink", &cmd_unlink, 1, 1 },

	{ "getcwd", &cmd_getcwd, 0, 0 },
	{ "chdir", &cmd_chdir, 1, 1 },
	{ "mkdir", &cmd_mkdir, 1, 1 },
	{ "rmdir", &cmd_rmdir, 1, 1 },

	{ "getid", &cmd_getid, 0, 0 },
	{ "setuid", &cmd_setuid, 1, 1 },
	{ "setgid", &cmd_setgid, 1, 1 },

	{ "hostname", &cmd_hostname, 0, 1 },
	{ "reboot", &cmd_reboot, 0, 0 },
	{ "shutdown", &cmd_shutdown, 0, 0 },
	{ "halt", &cmd_halt, 0, 0 },

	{ "lsfd", &cmd_lsfd, 0, 0 },
};

#define	HANDLERLIST_SIZE	(sizeof(handlerlist) / sizeof(struct __cmdhandler))


void cmd_help(int argc, char * argv[])
{
	printf(	"Available commands:\n"
		"    help                            Show this help screen\n"
		"    exec <cmd>                      Fork and execute a command\n"
		"    quit                            Exit the Impurity Demo shell\n"

		"\n"
		"    open <path>                     Open a file and return the file descriptor\n"
		"    lseek <fd> <offset> <whence>    Reposition <fd>\n"
		"    read <fd> [bytes]               Read <bytes> from file descriptor\n"
		"    write <fd> <bytes>              Write <bytes> to <fd>\n"
		"    close <fd>                      Close specified file descriptor\n"
		"    unlink <path>                   Remove specified file\n"

		"\n"
		"    getcwd                          Get current working directory\n"
		"    chdir <path>                    Change working directory to <path>\n"
		"    mkdir <path>                    Create <path> directory\n"
		"    rmdir <path>                    Remove <path> directory\n"

		"\n"
		"    getid                           Print information about [e][ug]id\n"
		"    setuid <uid>                    Set UID to <uid>\n"
		"    setgid <gid>                    Set GID to <gid>\n"

		"\n"
		"    hostname [name]                 Print (or set) the hostname.\n"
		"    reboot                          Reboot the computer.\n"
		"    shutdown                        Shutdown the computer.\n"
		"    halt                            Halt the computer.\n"

		"\n"
		"    lsfd                            Show information about open file descriptors\n");
}

void cmd_exec(int argc, char * argv[])
{
	system(argv[1]);
}

/* Taken from solar eclipse's vuln.c */
void cmd_lsfd(int argc, char * argv[])
{
	int fd;

	for(fd=0; fd <= 1024; fd++)
	{
		struct stat st;
		char perm[10] = "---------";

		if (fstat(fd, &st) == 0)
		{
			char *type, *p;
			char extra[1024];

			memset(extra, 0, sizeof(extra));

			if(S_ISREG(st.st_mode))
				type = "file";

			if(S_ISDIR(st.st_mode))
				type = "directory";

			if(S_ISCHR(st.st_mode))
			{
				type = "character";
				p = ttyname(fd);
				if (p != NULL)
					strncpy(extra, p, sizeof(extra));
			}

			if(S_ISBLK(st.st_mode))
				type = "block";

			if(S_ISFIFO(st.st_mode))
				type = "fifo";

			if(S_ISLNK(st.st_mode))
				type = "symlink";
            
			if(S_ISSOCK(st.st_mode))
			{
				char locip[16], remip[16];
				struct sockaddr_in loc, rem;
				int slen = sizeof(struct sockaddr);

				memset(locip, 0, sizeof(locip));
				memset(remip, 0, sizeof(remip));

				getsockname(fd, (struct sockaddr *)&loc, &slen);
				getpeername(fd, (struct sockaddr *)&rem, &slen);

				strncpy(locip, (char *) inet_ntoa(loc.sin_addr), sizeof(locip));
				strncpy(remip, (char *) inet_ntoa(rem.sin_addr), sizeof(remip));

				snprintf(extra, sizeof(extra), "%s:%u -> %s:%u", 
					locip, ntohs(loc.sin_port), 
					remip, ntohs(rem.sin_port));

				type = "socket";
			}

			if(st.st_mode & S_IRUSR) perm[0] = 'r';
			if(st.st_mode & S_IWUSR) perm[1] = 'w';
			if(st.st_mode & S_IXUSR) perm[2] = 'x';
			if(st.st_mode & S_IRGRP) perm[3] = 'r';
			if(st.st_mode & S_IWGRP) perm[4] = 'w';
			if(st.st_mode & S_IXGRP) perm[5] = 'x';
			if(st.st_mode & S_IROTH) perm[6] = 'r';
			if(st.st_mode & S_IWOTH) perm[7] = 'w';
			if(st.st_mode & S_IXOTH) perm[8] = 'x';

			printf("[%d] [%s] dev=%d ino=%d uid=%d gid=%d rdev=%d size=%d %s (%s)\n",
				fd,
				perm,
				st.st_dev,
				st.st_ino,
				st.st_uid,
				st.st_gid,
				st.st_rdev,
				st.st_size,
				type,
				extra);
		}
	}
}

void cmd_open(int argc, char * argv[])
{
	int fd;

	fd = open(argv[1], O_RDWR | O_CREAT | O_APPEND | O_LARGEFILE, S_IRWXU);
	if(fd == -1)
		fd = open(argv[1], O_RDONLY | O_LARGEFILE);

	if(fd == -1)
		perror(argv[1]);
	else
		printf("open: %d\n", fd);
}

void cmd_lseek(int argc, char * argv[])
{
	int fd, offset, whence;
	int ret;

	fd = atoi(argv[1]);
	offset = atoi(argv[2]);
	whence = -1;

	if(strcasecmp(argv[3], "SEEK_SET") == 0)
		whence = SEEK_SET;
	if(strcasecmp(argv[3], "SEEK_CUR") == 0)
		whence = SEEK_CUR;
	if(strcasecmp(argv[3], "SEEK_END") == 0)
		whence = SEEK_END;

	if(whence == -1)
	{
		printf("whence was not SEEK_SET, SEEK_CUR, or SEEK_END\n");
		return;
	}

	if((ret = lseek(fd, offset, whence)) == -1)
		perror("lseek");
	else
		printf("lseek: %i\n", ret);
}

void cmd_read(int argc, char * argv[])
{
	int fd, size;
	int read_out, rsz;
	char buf[512];

	fd = atoi(argv[1]);
	{ /* Get max length to read... ugly. */
		int cur, end;

		cur = lseek(fd, 0, SEEK_CUR);
		end = lseek(fd, 0, SEEK_END);

		size = end - cur;
		lseek(fd, cur, SEEK_SET);
	}
	if(argc > 1)
		size = atoi(argv[2]);

	for(rsz = 0; rsz < size;)
	{
		read_out = read(fd, buf, MIN(sizeof(buf), size - rsz));
		if(read_out == -1)
			return;
		write(1, buf, read_out);
		rsz += read_out;
	}
}

void cmd_write(int argc, char * argv[])
{
	int fd, size;
	int read_in, rsz;
	char buf[512];

	fd = atoi(argv[1]);
	size = atoi(argv[2]);

	for(rsz = 0; rsz < size;)
	{
		read_in = read(1, buf, MIN(sizeof(buf), size - rsz));
		if(read_in == -1)
			exit(0);
		write(fd, buf, read_in);
		rsz += read_in;
	}
}

void cmd_close(int argc, char * argv[])
{
	if(close(atoi(argv[1])) == -1)
		perror("close");
}

void cmd_unlink(int argc, char * argv[])
{
	if(unlink(argv[1]) == -1)
		perror("unlink");
}

void cmd_getcwd(int argc, char * argv[])
{
/* This should be big enough to accomodate all cases. */
	char buf[8192];

	if(getcwd(buf, sizeof(buf)) == NULL)
		perror("getcwd");
	else
		printf("%s\n", buf);
}

void cmd_chdir(int argc, char * argv[])
{
	if(chdir(argv[1]) == -1)
		perror(argv[1]);
}

void cmd_mkdir(int argc, char * argv[])
{
	if(mkdir(argv[1], 0755) == -1)
		perror(argv[1]);
}

void cmd_rmdir(int argc, char * argv[])
{
	if(rmdir(argv[1]) == -1)
		perror(argv[1]);
}

void cmd_getid(int argc, char * argv[])
{
	struct passwd * pwd;
	struct group * grp;

	printf("uid=%u", getuid());
	if((pwd = getpwuid(getuid())) != NULL)
		printf("(%s)", pwd->pw_name);

	printf(" gid=%u", getgid());
	if((grp = getgrgid(getgid())) != NULL)
		printf("(%s)", grp->gr_name);

	if(geteuid() != getuid())
	{
		printf(" euid=%u", geteuid());
		if((pwd = getpwuid(geteuid())) != NULL)
			printf("(%s)", pwd->pw_name);
	}
	if(getegid() != getgid())
	{
		printf(" egid=%u", getegid());
		if((grp = getgrgid(getegid())) != NULL)
			printf("(%s)", grp->gr_name);
	}

	putchar('\n');
}

void cmd_setuid(int argc, char * argv[])
{
	if(setuid(atoi(argv[1])) == -1)
		perror("setuid");
}

void cmd_setgid(int argc, char * argv[])
{
	if(setgid(atoi(argv[1])) == -1)
		perror("setgid");
}

void cmd_hostname(int argc, char * argv[])
{
/* This should be big enough to accomodate all cases. */
	char buf[8192];

	if(argc > 1)
	{
		if(sethostname(argv[1], strlen(argv[1])) == -1)
			perror("sethostname");
	}
	else
	{
		if(gethostname(buf, sizeof(buf)) == -1)
			perror("gethostname");
		else
			printf("%s\n", buf);
	}
}

void cmd_reboot(int argc, char * argv[])
{
	sync();
#ifdef SYSCALL_REBOOT
	if(reboot(0xfee1dead, 0x28121969, 0x01234567, NULL) == -1)
#else
	if(reboot(0x01234567) == -1)
#endif
		perror("reboot");
}

/* Linux >= 2.1.30 */
void cmd_shutdown(int argc, char * argv[])
{
	sync();
#ifdef SYSCALL_REBOOT
	if(reboot(0xfee1dead, 0x28121969, 0x4321fedc, NULL) == -1)
#else
	if(reboot(0x4321fedc) == -1)
#endif
		perror("reboot");
}

/* Linux >= 1.1.76 */
void cmd_halt(int argc, char * argv[])
{
	sync();
#ifdef SYSCALL_REBOOT
	if(reboot(0xfee1dead, 0x28121969, 0xcdef0123, NULL) == -1)
#else
	if(reboot(0xcdef0123) == -1)
#endif
		perror("reboot");
}

void cmd_quit(int argc, char * argv[])
{
	exit(0);
}

#define	MAX_ARGV	15

int main (int argc, char **argv)
{
	setvbuf(stdout, (char *)NULL, _IONBF, 0);
	printf("--=[ Impurity Demo Shell\n");
    
	while(1)
	{
		char cmd[2048];
		char * argv[MAX_ARGV];
		int argc;

		int i, hit;
        
		printf("impurity demo > ");

		memset(cmd, 0, sizeof(cmd));
		if(fgets(cmd, sizeof(cmd), stdin) == NULL)
			exit(0);
		parse(cmd, &argc, argv);
		if(argc == 0)
			continue;

		for(hit = i = 0; i < HANDLERLIST_SIZE; i++)
		{
			if(strcmp(argv[0], handlerlist[i].cmd) == 0)
			{
				hit = 1;

				if(argc > handlerlist[i].arg_max+1)
					printf("%s: Too many arguments\n", argv[0]);
				else if(argc < handlerlist[i].arg_min+1)
					printf("%s: Too few arguments\n", argv[0]);
				else
					handlerlist[i].handler(argc, argv);
			}
		}

		if(hit == 0)
		{
			printf("%s: Unknown command.\n", argv[0]);
		}
	}
}

void parse(char * str, int * const argc, char * argv[])
{
	*argc = 0;

	if(strlen(str) > 0 && str[strlen(str) - 1] == '\n')
		str[strlen(str) - 1] = '\0';
	if(strlen(str) > 0 && str[strlen(str) - 1] == '\r')
		str[strlen(str) - 1] = '\0';

	if(strlen(str) == 0)
		return;

	for(argv[(*argc)++] = str; strlen(str) && *argc < MAX_ARGV; str++)
	{
		if(*str == ' ')
		{
			*str = '\0';
			argv[(*argc)++] = str+1;
		}
		if(*str == '\\')
		{
			switch(*(str + 1))
			{
//				case 'n':
//					break;
				default:
					memmove(str, str+1, strlen(str));
					break;
			}
		}
	}
}
