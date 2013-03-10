all: econproxy

econproxy: econproxy.c util.c util.h econproto.h
	gcc -ggdb -Wall -o $@ econproxy.c util.c

epserv: epserv.c econproto.h
	gcc -ggdb -Wall -o $@ $<
