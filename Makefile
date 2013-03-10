all: econproxy econserv

econproxy: econproxy.c util.c util.h econproto.h
	gcc -ggdb -Wall -o $@ econproxy.c util.c

econserv: econserv.c util.c util.h econproto.h 
	gcc -ggdb -Wall -o $@ $< util.c

clean:
	rm -f econproxy econserv
