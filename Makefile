CFLAGS=-std=gnu99 -ggdb -Wall -Wstrict-prototypes -Wmissing-prototypes -Wunused-result -Wextra -pedantic

all: econproxy econserv econfind

%: %.c util.c util.h econproto.h econpacket.c econpacket.h
	gcc $(CFLAGS) -o $@ $< util.c econpacket.c

clean:
	rm -f econproxy econserv econfind
