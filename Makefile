all: econproxy epserv

econproxy: econproxy.c util.c util.h econproto.h
	gcc -ggdb -Wall -o $@ econproxy.c util.c

epserv: epserv.c util.c util.h econproto.h 
	gcc -ggdb -Wall -o $@ $< util.c
