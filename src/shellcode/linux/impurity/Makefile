all: shelldemo tracepath

.c.o:
	gcc -c $<

shelldemo: shelldemo.c
	diet gcc -Wl,-T,script-ld-impurity -o shelldemo shelldemo.c -s -static
	/sbin/chpax -m shelldemo >/dev/null 2>&1 || true

tracepath: tracepath.c
	diet gcc -Wl,-T,script-ld-impurity -o tracepath tracepath.c -s -static
	/sbin/chpax -m shelldemo >/dev/null 2>&1 || true

clean:
	rm -f *.o shelldemo tracepath
