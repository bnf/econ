#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <assert.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/uio.h>
#include <unistd.h>
#include <netdb.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>

#include <poll.h>

#include "econproto.h"

#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#define ARRAY_SIZE(arr) (sizeof (arr) / sizeof ((arr)[0]))

struct ep {
	int vnc_mfd;
	int vnc_fd;

	struct iovec iov[3];
};


/* From systemd:src/shared/util.c */

static ssize_t
loop_read(int fd, void *buf, size_t nbytes, uint8_t do_poll) {
        uint8_t *p;
        ssize_t n = 0;

        assert(fd >= 0);
        assert(buf);

        p = buf;

        while (nbytes > 0) {
                ssize_t k;

                if ((k = read(fd, p, nbytes)) <= 0) {

                        if (k < 0 && errno == EINTR)
                                continue;

                        if (k < 0 && errno == EAGAIN && do_poll) {
                                struct pollfd pollfd;

                                memset(&pollfd, 0, sizeof pollfd);
                                pollfd.fd = fd;
                                pollfd.events = POLLIN;

                                if (poll(&pollfd, 1, -1) < 0) {
                                        if (errno == EINTR)
                                                continue;

                                        return n > 0 ? n : -errno;
                                }

                                if (pollfd.revents != POLLIN)
                                        return n > 0 ? n : -EIO;

                                continue;
                        }

                        return n > 0 ? n : (k < 0 ? -errno : 0);
                }

                p += k;
                nbytes -= k;
                n += k;
        }

        return n;
}

static void
write_ppm(FILE *img, int width, int height, int bpp, uint8_t *buf)
{
	int i;

	fprintf(img, "P6\n");
	fprintf(img, "%d %d\n255\n", width, height);

	for (i = 0; i < width * height; ++i) {
		fwrite(&buf[i*bpp+2], 1, 1, img);
		fwrite(&buf[i*bpp+1], 1, 1, img);
		fwrite(&buf[i*bpp+0], 1, 1, img);
	}
}


static int
bind_socket(int socktype, char *host, char *port)
{
	struct addrinfo hints, *result, *rp;
	int reuseaddr = 1, s;
	int fd;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = socktype;

	s = getaddrinfo(host, port, &hints, &result);
	if (s != 0) {
		fprintf(stderr, "getaddrinfo :%s\n", gai_strerror(s));
		return -1;
	}
	for (rp = result; rp != NULL; rp = rp->ai_next) {
		fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (fd == -1)
			continue;
		if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
			       &reuseaddr, sizeof(reuseaddr)) == -1)
			continue;

		/*ip = ((struct sockaddr_in *)rp->ai_addr)->sin_addr.s_addr;*/
		if (bind(fd, rp->ai_addr, rp->ai_addrlen) == 0)
			break;

		close(fd);
	}
	freeaddrinfo(result);
	if (rp == NULL) {
		fprintf(stderr, "Failed to bind: %s\n", strerror(errno));
		return -1;
	}

	return fd;
}

int
main(int argc, char *argv[])
{
	struct ep ep;
	int len;

	memset(&ep, 0, sizeof ep);

	ep.vnc_mfd = bind_socket(SOCK_STREAM, "localhost", "5500");
	if (ep.vnc_mfd < 0)
		exit(EXIT_FAILURE);
	if (listen(ep.vnc_mfd, 1) != 0)
		exit(EXIT_FAILURE);


	ep.vnc_fd = accept(ep.vnc_mfd, NULL, NULL);
	if (ep.vnc_fd < 0)
		exit(EXIT_FAILURE);

	char client_protocol[12];
	read(ep.vnc_fd, client_protocol, sizeof client_protocol);

	const char *rfb_protocol = "RFB 003.008\n";
	write(ep.vnc_fd, rfb_protocol, strlen(rfb_protocol));

	char security_types[BUFSIZ];
	len = read(ep.vnc_fd, security_types, BUFSIZ);
	printf("security_types: %d\n", len);

#define NOAUTH 1
	uint8_t auth = NOAUTH;
	write(ep.vnc_fd, &auth, sizeof auth);

	uint32_t auth_result = 0;

	len = read(ep.vnc_fd, &auth_result, sizeof auth_result);
	if (auth_result != 0) {
		fprintf(stderr, "auth failed: %d, %d\n", auth_result, len);
		exit(EXIT_FAILURE);
	}

	uint8_t share_desktop = 1;
	write(ep.vnc_fd, &share_desktop, sizeof share_desktop);
	
	union init {
		rfbServerInitMsg msg;
		struct {
			rfbServerInitMsg msg;
			char name[0];
		} d;
		char buf[BUFSIZ];
	};
	union init init;


	len = read(ep.vnc_fd, &init, sizeof init);
	printf("read init: %d\n", len);

	printf("w: %hu, h: %hu\n", ntohs(init.msg.framebufferWidth), ntohs(init.msg.framebufferHeight));

	
	struct {
		uint8_t cmd;
		uint8_t padding1;
		uint16_t padding2;
	} cmd_set_pixel_format = { 0, 0, 0 };

	ep.iov[0].iov_base = &cmd_set_pixel_format;
	ep.iov[0].iov_len = sizeof cmd_set_pixel_format;
	ep.iov[1].iov_base = &init.msg.format;
	ep.iov[1].iov_len = sizeof init.msg.format;

	writev(ep.vnc_fd, ep.iov, 2);

	struct {
		uint8_t cmd;
		uint8_t padding;
		uint16_t number_of_encodings;
		uint32_t encodings[2];
	} cmd_set_encodings = {
		2, 0, htons(2),
#if 1
		{ htonl(0) /* RAW */, htonl(7) /* Tight */ }
#else
		{ htonl(7) /* Tight */, htonl(0) /* RAW */ }
#endif
	};

	write(ep.vnc_fd, &cmd_set_encodings, sizeof cmd_set_encodings);

	struct {
		uint8_t cmd;
		uint8_t incremental;
		uint16_t x, y, w, h;
	} framebuffer_update_request = {
		3, 0,
		htons(0), htons(0), htons(1024), htons(768)
	};
	write(ep.vnc_fd, &framebuffer_update_request, sizeof framebuffer_update_request);

	struct framebuffer_update {
		uint8_t cmd;
		uint8_t padding;
		uint16_t nrects;
	} framebuffer_update;

	struct rect {
		uint16_t x, y, w, h;
		int32_t encoding;
		uint8_t data[0];
	};

#if 0
	ep.iov[0].iov_base = &framebuffer_update;
	ep.iov[0].iov_len = sizeof framebuffer_update;
	ep.iov[1].iov_base = buf;
	ep.iov[1].iov_len = bufsiz;
#endif

	len = read(ep.vnc_fd, &framebuffer_update, sizeof framebuffer_update);
	//len = readv(ep.vnc_fd, ep.iov, 2);
	printf("read framebuffer update?: %d\n", len);

	framebuffer_update.nrects = ntohs(framebuffer_update.nrects);
	printf("cmd: %d, nrects: %d\n", framebuffer_update.cmd, ntohs(framebuffer_update.nrects));

	size_t bufsiz = framebuffer_update.nrects * (sizeof(struct rect) + 1024 * 768 * init.msg.format.bitsPerPixel/8);
	char *buf = malloc(bufsiz);
	assert(buf != NULL);

	len = loop_read(ep.vnc_fd, buf, bufsiz, 0);
	printf("read framebuffer update data?: %d\n", len);

	struct rect *rect = (void *) buf;
	printf("x: %d, y: %d, w: %d, h: %d, encoding: %d\n",
	       ntohs(rect->x), ntohs(rect->y), ntohs(rect->w), ntohs(rect->h), ntohl(rect->encoding));

	FILE *img = fopen("/tmp/out.ppm", "w");
	write_ppm(img, 1024, 768, 4, buf);
	fclose(img);


	/*
	len = read(ep.vnc_fd, buf, bufsiz);
	printf("read framebuffer update data?: %d\n", len);

	while (len > 0) {
		len = read(ep.vnc_fd, buf, bufsiz);
		printf("read framebuffer update data?: %d\n", len);
	}
	*/

	pause();
}
