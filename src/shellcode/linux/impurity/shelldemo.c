/*
#
# Copyright (C) 2003, 2004 H D Moore / METASPLOIT.COM
# This file is part of the Metasploit Exploit Framework.
#
*/

/* cheesy little demo shell for testing the impurity system */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>


/* this was taken from solar eclipse's vuln.c */
void scanfds (void)
{
    int x;
    for (x=0; x<=1024; x++)
    {
        int ch, n;
        struct stat st;
        char perm[10] = "---------";

        if (fstat(x, &st) == 0)
        {
            char *type, *p;
            char extra[1024];
            
            memset(extra, 0, sizeof(extra));
            
            if (S_ISREG(st.st_mode))
                type = "file";
            
            if (S_ISDIR(st.st_mode))
                type = "directory";
            
            if (S_ISCHR(st.st_mode))
            {
                type = "character";
                p = ttyname(x);
                if (p != NULL)
                    strncpy(extra, p, sizeof(extra));
            }
            
            if (S_ISBLK(st.st_mode))
                type = "block";
            
            if (S_ISFIFO(st.st_mode))
                type = "fifo";
            
            if (S_ISLNK(st.st_mode))
                type = "symlink";
            
            if (S_ISSOCK(st.st_mode))
            {
                char locip[16], remip[16];
                struct sockaddr_in loc, rem;
                int slen = sizeof(struct sockaddr);
                
                memset(locip, 0, sizeof(locip));
                memset(remip, 0, sizeof(remip));
                
                getsockname(x, &loc, &slen);
                getpeername(x, &rem, &slen);
                
                strncpy(locip, (char *) inet_ntoa(loc.sin_addr), sizeof(locip));
                strncpy(remip, (char *) inet_ntoa(rem.sin_addr), sizeof(remip));
                
                snprintf(extra, sizeof(extra), "%s:%u -> %s:%u", 
                        locip, ntohs(loc.sin_port), 
                        remip, ntohs(rem.sin_port));
                
                type = "socket";
                
            }

            if (st.st_mode & S_IRUSR) perm[0] = 'r';
            if (st.st_mode & S_IWUSR) perm[1] = 'w';
            if (st.st_mode & S_IXUSR) perm[2] = 'x';
            if (st.st_mode & S_IRGRP) perm[3] = 'r';
            if (st.st_mode & S_IWGRP) perm[4] = 'w';
            if (st.st_mode & S_IXGRP) perm[5] = 'x';
            if (st.st_mode & S_IROTH) perm[6] = 'r';
            if (st.st_mode & S_IWOTH) perm[7] = 'w';
            if (st.st_mode & S_IXOTH) perm[8] = 'x';

            printf("[%d] [%s] dev=%d ino=%d uid=%d gid=%d rdev=%d size=%d %s (%s)\n",
                    x,
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


int main (int argc, char **argv)
{
    setvbuf(stdout, (char *)NULL, _IONBF, 0);
    printf("--=[ Impurity Demo Shell\n");
    
    while (1)
    {
        char cmd[1024];
        char *p;
        int i,x;
        
        printf("impurity demo > ");
        
        memset(cmd, 0, sizeof(cmd));
        fgets(cmd, sizeof(cmd), stdin);
        while(p=strstr(cmd, "\n")) *p = 0;
        p = cmd;
        
        if (strlen(cmd)== 4 && (strncmp("quit", cmd, 4) == 0 || strncmp("exit", cmd, 4) == 0)) exit(0);
        if (strlen(cmd)== 4 && (strncmp("help", cmd, 4) == 0))
        {
            printf("Available Commands:\n"
                   "   exec  <cmd>          Fork and execute a command\n"
                   "   lsfd                 Show all open file descriptors\n"
                   "   open  <path>         Open a file and return the file descriptor\n"
                   "   read  <fd> [bytes]   Read <bytes> from file descriptor\n"
                   "   write <fd> <bytes>   Write <bytes> to file descriptor\n"
                   "   close <fd>           Close a specified file descriptor\n"
                   "   unlink <path>        Remove the specified file\n"
                   "   help                 Show this help screen\n"
                   "   quit                 Exit the Impurity Demo shell\n"
                   );
        }
        
        if (strlen(cmd) > 6 && strncmp("exec ", cmd, 5) == 0)
        {
            p += 5;
            printf("[*] executing %s\n", p);
            system(p);
        }
        
        if (strlen(cmd)>= 4 && (strncmp("lsfd", cmd, 4) == 0)) scanfds();
        if (strlen(cmd)>= 5 && (strncmp("close", cmd, 5) == 0))
        {
            int fd;
            p += 6;
            fd = atoi(p);
            close(fd);
        }
        if (strlen(cmd)>= 6 && (strncmp("unlink", cmd, 6) == 0))
        {
            int fd;
            p += 7;
            unlink(p);
        }
           
        if (strlen(cmd)>= 4 && (strncmp("open", cmd, 4) == 0))
        {
            int fd;
            p += 5;
            
            fd = open(p, O_RDWR|O_CREAT|O_APPEND|O_LARGEFILE, S_IRWXU);
            if (fd == -1)  fd = open(p, O_RDONLY|O_LARGEFILE);
            if (fd == -1)
            {
                printf("OPEN: ERROR [%s]\n", p);
            } else {
                printf("OPEN: %d\n", fd);
            }
        }
        
        if (strlen(cmd)>= 4 && (strncmp("read", cmd, 4) == 0))
        {
            int fd, sz = 0;
            char *t;
            p += 5;
            
            fd = atoi(p);
            t = strstr(p, " ");
            if (t++ != NULL) sz = atoi(t);
            lseek(fd, 0, 0);
            
            /* read from fd and write to stdout */
            {
                int res, cnt, rsz;
                char rbuff[2048];
                memset(rbuff, 0, sizeof(rbuff));
                res = cnt = rsz = 0;
                
                while ((cnt < sz && sz != 0) || sz == 0)
                {
                    
                    rsz = sz - cnt < sizeof(rbuff) ? sz - cnt : sizeof(rbuff);
                    if (sz == 0) rsz = sizeof(rbuff);
                    res = read(fd, rbuff, rsz);
                    if (res <=0) break;
                    cnt += res;
                    write(1, rbuff, res);
                }
                printf("READ: %d\n", cnt);
            }
        }
        
        if (strlen(cmd)>= 5 && (strncmp("write", cmd, 5) == 0))
        {
            int fd, sz = 0;
            char *t;
            p += 6;
            
            fd = atoi(p);
            t = strstr(p, " ");
            if (t++ != NULL) sz = atoi(t);

            if (sz == 0)
            {
                printf("WRITE: ERROR\n");
            } else {
                
                /* read from stdin and write to fd */
                {
                    int res, cnt, rsz;
                    char rbuff[2048];
                    memset(rbuff, 0, sizeof(rbuff));
                    res = cnt = rsz = 0;
                    while (cnt < sz)
                    {
                        rsz = sz - cnt < sizeof(rbuff) ? sz - cnt : sizeof(rbuff);
                        res = read(0, rbuff, rsz);
                        if (res <= 0) break;
                        write(fd, rbuff, res);
                        cnt += res;
                    }
                    printf("WRITE: %d\n", cnt);
                }
            }
        }
    }
    
    return(0);
}
