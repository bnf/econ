CFLAGS=-std=gnu99 -ggdb -Wall -Wstrict-prototypes -Wmissing-prototypes -Wunused-result -Wextra -pedantic

all: econproxy econserv

%: %.c util.c util.h econproto.h
	gcc $(CFLAGS) -o $@ $< util.c

clean:
	rm -f econproxy econserv
