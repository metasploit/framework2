all: tracepath

.c.o:
	gcc -c $<

tracepath: tracepath.c
	diet gcc -Wl,-T,script-ld-impurity -o tracepath tracepath.c -s -static
	/sbin/chpax -m shelldemo >/dev/null 2>&1 || true

clean:
	rm -f *.o tracepath
