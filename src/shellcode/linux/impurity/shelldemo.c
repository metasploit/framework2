/*
 * Copyright (c) 2005 vlad902 <vlad902 [at] gmail.com>
 * This file is part of the Metasploit Framework.
 */

/*
 * This doesn't do very complex input parsing so if you forget to pass a command
 *   an argument... pray.
 */

#include <sys/types.h>
#include <sys/stat.h>
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

#define	MIN(a, b)		((a) < (b) ? (a) : (b))

char * chomp(char * const);

void cmd_help(const char *);
void cmd_exec(const char *);

void cmd_lsfd(const char *);
void cmd_close(const char *);
void cmd_open(const char *);
void cmd_lseek(const char *);
void cmd_read(const char *);
void cmd_write(const char *);
void cmd_unlink(const char *);

void cmd_getcwd(const char *);
void cmd_chdir(const char *);
void cmd_mkdir(const char *);
void cmd_rmdir(const char *);

void cmd_getid(const char *);
void cmd_setuid(const char *);
void cmd_setgid(const char *);

void cmd_quit(const char *);

struct __cmdhandler
{
	char * cmd;
	void (* handler)(const char *);
};

/* XXX: symlink, (link?), chown, chmod, rename, move, stat, kill, (ps?), (ls?) */
/* XXX: mkdir take arg for perms? open? */
struct __cmdhandler handlerlist[] =
{
	{ "help", &cmd_help },
	{ "exec", &cmd_exec },

	{ "lsfd", &cmd_lsfd },
	{ "open", &cmd_open },
	{ "lseek", &cmd_lseek },
	{ "read", &cmd_read },
	{ "write", &cmd_write },
	{ "close", &cmd_close },
	{ "unlink", &cmd_unlink },

	{ "getcwd", &cmd_getcwd },
	{ "chdir", &cmd_chdir },
	{ "mkdir", &cmd_mkdir },
	{ "rmdir", &cmd_rmdir },

	{ "getid", &cmd_getid },
	{ "setuid", &cmd_setuid },
	{ "setgid", &cmd_setgid },

	{ "quit", &cmd_quit },
	{ "exit", &cmd_quit },
};

#define	HANDLERLIST_SIZE	(sizeof(handlerlist) / sizeof(struct __cmdhandler))


void cmd_help(const char * arg)
{
	printf(	"Available commands:\n"
		"    help                            Show this help screen\n"
		"    exec <cmd>                      Fork and execute a command\n"

		"\n"
		"    lsfd                            Show information about open file descriptors\n"
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
		"    quit                            Exit the Impurity Demo shell\n");
}

void cmd_exec(const char * arg)
{
	system(arg);
}

/* Taken from solar eclipse's vuln.c */
void cmd_lsfd(const char * arg)
{
	int fd;

	for(fd=0; fd <= 1024; fd++)
	{
		int ch, n;
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

void cmd_open(const char * arg)
{
	int fd;

	fd = open(arg, O_RDWR | O_CREAT | O_APPEND | O_LARGEFILE, S_IRWXU);
	if(fd == -1)
		fd = open(arg, O_RDONLY | O_LARGEFILE);

	if(fd == -1)
		perror(arg);
	else
		printf("open: %d\n", fd);
}

void cmd_lseek(const char * arg)
{
	int fd, offset, whence;
	int ret;

	fd = atoi(arg);
	if((arg = strchr(arg, ' ')) == NULL)
	{
		printf("lseek: Incorrect argument format\n");
		return;
	}
	arg++;
	offset = atoi(arg);
	if((arg = strchr(arg, ' ')) == NULL)
	{
		printf("lseek: Incorrect argument format\n");
		return;
	}
	arg++;
	whence = -1;
	if(strncasecmp(arg, "SEEK_SET", 8) == 0)
		whence = SEEK_SET;
	if(strncasecmp(arg, "SEEK_CUR", 8) == 0)
		whence = SEEK_CUR;
	if(strncasecmp(arg, "SEEK_END", 8) == 0)
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

void cmd_read(const char * arg)
{
	int fd, size;
	int read_out, rsz;
	char buf[512];

	fd = atoi(arg);
	{ /* Get max length to read... ugly. */
		int cur, end;

		cur = lseek(fd, 0, SEEK_CUR);
		end = lseek(fd, 0, SEEK_END);

		size = end - cur;
		lseek(fd, cur, SEEK_SET);
	}
	if((arg = strchr(arg, ' ')) != NULL)
		size = atoi(arg + 1);

	for(rsz = 0; rsz < size;)
	{
		read_out = read(fd, buf, MIN(sizeof(buf), size - rsz));
		if(read_out == -1)
			return;
		write(1, buf, read_out);
		rsz += read_out;
	}
}

void cmd_write(const char * arg)
{
	int fd, size;
	int read_in, rsz;
	char buf[512];

	fd = atoi(arg);
	if((arg = strchr(arg, ' ')) == NULL)
		printf("write: Incorrect argument format\n");

	size = atoi(arg + 1);

	for(rsz = 0; rsz < size;)
	{
		read_in = read(1, buf, MIN(sizeof(buf), size - rsz));
		if(read_in == -1)
			exit(0);
		write(fd, buf, read_in);
		rsz += read_in;
	}
}

void cmd_close(const char * arg)
{
	if(close(atoi(arg)) == -1)
		perror("close");
}

void cmd_unlink(const char * arg)
{
	if(unlink(arg) == -1)
		perror("unlink");
}

void cmd_getcwd(const char * arg)
{
/* This should be big enough to accomodate all cases. */
	char buf[8192];

	if(getcwd(buf, sizeof(buf)) == NULL)
		perror("getcwd");
	else
		puts(buf);
}

void cmd_chdir(const char * arg)
{
	if(chdir(arg) == -1)
		perror(arg);
}

void cmd_mkdir(const char * arg)
{
	if(mkdir(arg, 0755) == -1)
		perror(arg);
}

void cmd_rmdir(const char * arg)
{
	if(rmdir(arg) == -1)
		perror(arg);
}

void cmd_getid(const char * arg)
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

void cmd_setuid(const char * arg)
{
	if(setuid(atoi(arg)) == -1)
		perror("setuid");
}

void cmd_setgid(const char * arg)
{
	if(setgid(atoi(arg)) == -1)
		perror("setgid");
}

void cmd_quit(const char * arg)
{
	exit(0);
}

int main (int argc, char **argv)
{
	setvbuf(stdout, (char *)NULL, _IONBF, 0);
	printf("--=[ Impurity Demo Shell\n");
    
	while(1)
	{
		char cmd[1024];
		int i, hit;
        
		printf("impurity demo > ");

		memset(cmd, 0, sizeof(cmd));
		if(fgets(cmd, sizeof(cmd), stdin) == NULL)
			exit(0);
		chomp(cmd);
		if(strlen(cmd) == 0)
			continue;

		for(hit = i = 0; i < HANDLERLIST_SIZE; i++)
		{
			if(strncmp(cmd, handlerlist[i].cmd, strlen(handlerlist[i].cmd)) == 0)
			{
				hit = 1;
				handlerlist[i].handler(cmd + strlen(handlerlist[i].cmd) + 1);
			}
		}

		if(hit == 0)
		{
			if(strchr(cmd, ' ') != NULL)
				*(strchr(cmd, ' ')) = '\0';

			printf("%s: Unknown command.\n", cmd);
		}
	}
}

char * chomp(char * const str)
{
	if(str[strlen(str) - 1] == '\n')
		str[strlen(str) - 1] = '\0';
	if(str[strlen(str) - 1] == '\r')
		str[strlen(str) - 1] = '\0';

	return str;
}
