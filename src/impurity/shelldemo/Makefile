SRC	= cmd_base.c cmd_expl.c cmd_fd.c cmd_fs.c cmd_misc.c \
          cmd_privs.c cmd_proc.c cmd_sys.c main.c misc.c
	  	  
CFLAGS	= -Wall -s -static
LDFALGS = -Wl,-T,../script-ld-impurity 

BIN	= $(SRC:.c=.o)

all: clean ${BIN} shelldemo

%.o: %.c
	diet $(CC) -c $(CFLAGS) $*.c

shelldemo:
	diet $(CC) $(CFLAGS) $(LDFLAGS) -o shelldemo *.o
	/sbin/chpax -m shelldemo >/dev/null 2>&1 || true
clean:
	rm -f shelldemo *.o
