SRC	= cmd_base.c cmd_expl.c cmd_fd.c cmd_fs.c cmd_misc.c \
          cmd_privs.c cmd_proc.c cmd_sys.c main.c misc.c
	  	  
CFLAGS	= -Wall
BIN	= $(SRC:.c=.o)

all: clean ${BIN} shelldemo

%.o: %.c
	diet $(CC) -c $(CFLAGS) $*.c

shelldemo:
	diet $(CC) $(CFLAGS) -o shelldemo *.o

clean:
	rm -f shelldemo *.o
