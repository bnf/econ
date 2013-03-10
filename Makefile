CFLAGS=-ggdb -Wall -Wstrict-prototypes -Wmissing-prototypes

all: econproxy econserv

%: %.c util.c util.h econproto.h
	gcc $(CFLAGS) -Wall -o $@ $< util.c

clean:
	rm -f econproxy econserv
