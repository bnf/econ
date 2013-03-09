#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <assert.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
#include <arpa/inet.h>

#if 0
#include <limits.h>
#endif

#include "econproto.h"
#include "util.h"

struct ep {
	int vnc_mfd;
	int vnc_fd;

	int ec_fd;
	int ec_sfd;

	int video_fd;
	int audio_fd;

	struct iovec iov[3];
	struct econ_header ehdr;
	struct econ_command ecmd;
	struct econ_record erec;

	uint8_t projUniqInfo[ECON_UNIQINFO_LENGTH];	
};


static void
init_header(struct econ_header *ehdr, int commandID)
{
	memset(ehdr, 0, sizeof *ehdr);

	strncpy(ehdr->magicnum, ECON_MAGIC_NUMBER,  ECON_MAGICNUM_SIZE);
	strncpy(ehdr->version,  ECON_PROTO_VERSION, ECON_PROTOVER_MAXLEN);

	ehdr->datasize = 0;
	ehdr->commandID = commandID;
}

static void
init_iov(struct ep *ep)
{
	ep->iov[0].iov_base = &ep->ehdr;
	ep->iov[0].iov_len = sizeof ep->ehdr;
	ep->iov[1].iov_base = &ep->ecmd;
	ep->iov[1].iov_len = sizeof ep->ecmd;
	ep->iov[2].iov_base = &ep->erec;
	ep->iov[2].iov_len = sizeof ep->erec;
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
ep_keepalive(struct ep *ep)
{
	init_iov(ep);
	init_header(&ep->ehdr, E_CMD_KEEPALIVE);
	set_ip(ep->ehdr.IPaddress, sock_get_ipv4_addr(ep->ec_fd));

	if (writev(ep->ec_fd, ep->iov, 1) < 0)
		return -1;

	return 0;
}

static int
ep_get_clientinfo(struct ep *ep)
{
	char buf[BUFSIZ], buf2[BUFSIZ];
	size_t len;

	init_iov(ep);
	init_header(&ep->ehdr, E_CMD_IPSEARCH);
	set_ip(ep->ehdr.IPaddress, sock_get_ipv4_addr(ep->ec_fd));
	ep->ehdr.datasize = 0;

	writev(ep->ec_fd, ep->iov, 1);

	len = read(ep->ec_fd, buf, BUFSIZ);
	struct econ_header *hdr = (void *) buf;
	printf("cmd: %d, len: %zd\n", hdr->commandID, len);

	if (len < (sizeof (struct econ_header) +
		   sizeof (struct econ_command) +
		   sizeof (struct econ_record))) {
		fprintf(stderr, "error: Invalid packet received.\n");
		return -1;
	}

	struct econ_command *ecmd = (void *) (buf + sizeof (struct econ_header));
	printf("clientinfo unknown value: %hu\n",
	       ecmd->command.clientinfo.unknown_field_1);
	/* cache projUniqInfo needed for reqconnect */
	struct econ_record *erec = (void *) (buf + sizeof (struct econ_header) +
					     sizeof (struct econ_command));
	memcpy(ep->projUniqInfo, erec->projUniqInfo, ECON_UNIQINFO_LENGTH);

#if 1
	len = read(ep->ec_fd, buf2, BUFSIZ);
	hdr = (void *) buf2;
	printf("cmd: %d, len: %zd\n", hdr->commandID, len);
#endif

	return 0;
}

static void
vnes_ntoh(rfbServerInitMsg *vnes1, rfbServerInitMsg *vnes2)
{
	memset(vnes2, 0, sizeof *vnes2);

	vnes2->framebufferWidth     = ntohs(vnes1->framebufferWidth);
	vnes2->framebufferHeight    = ntohs(vnes1->framebufferHeight);
	vnes2->format.bitsPerPixel  = vnes1->format.bitsPerPixel;
	vnes2->format.depth         = vnes1->format.depth;
	vnes2->format.bigEndian     = vnes1->format.bigEndian;
	vnes2->format.trueColour    = vnes1->format.trueColour != 0;

	vnes2->format.redMax        = ntohs(vnes1->format.redMax);
	vnes2->format.greenMax      = ntohs(vnes1->format.greenMax);
	vnes2->format.blueMax       = ntohs(vnes1->format.blueMax);
	
	vnes2->format.redShift      = vnes1->format.redShift;	
	vnes2->format.greenShift    = vnes1->format.greenShift;
	vnes2->format.blueShift     = vnes1->format.blueShift;

	vnes2->nameLength           = ntohl(vnes1->nameLength);
}

static int
ep_reqconnect(struct ep *ep, rfbServerInitMsg *vnes)
{
	init_iov(ep);
	init_header(&ep->ehdr, E_CMD_REQCONNECT);

	set_ip(ep->ehdr.IPaddress, sock_get_ipv4_addr(ep->ec_fd));
	ep->ehdr.datasize = sizeof ep->ecmd + sizeof ep->erec;

	memset(&ep->ecmd, 0, sizeof ep->ecmd);
	memset(&ep->erec, 0, sizeof ep->erec);

	vnes_ntoh(vnes, &ep->ecmd.command.reqconnect.vnesInitMsg);

	ep->ecmd.recordCount = 1;
	set_ip(ep->erec.IPaddress, sock_get_peer_ipv4_addr(ep->ec_fd));

	set_ip(ep->ecmd.command.reqconnect.subnetMask,
	       sock_get_netmask(ep->ec_fd));

#if 1
	/* FIXME: need to set gateway address? */
	ep->ecmd.command.reqconnect.gateAddress[0] = 192;
	ep->ecmd.command.reqconnect.gateAddress[1] = 168;
	ep->ecmd.command.reqconnect.gateAddress[2] = 1;
	ep->ecmd.command.reqconnect.gateAddress[3] = 1;
#endif

	ep->ecmd.command.reqconnect.unknown_field_1 = 0x02;
	ep->ecmd.command.reqconnect.unknown_field_2 = 0x01;
	ep->ecmd.command.reqconnect.unknown_field_3 = 0x03;

	memcpy(ep->erec.projUniqInfo, ep->projUniqInfo, ECON_UNIQINFO_LENGTH);
#if 0
	memcpy(ep->ecmd.command.reqconnect.EncPassword, "82091965",
	       ECON_ENCRYPTION_MAXLEN);
#endif

	writev(ep->ec_fd, ep->iov, 3);

	readv(ep->ec_fd, ep->iov, 3);
	if (ep->ehdr.commandID != E_CMD_CONNECTED) {
		fprintf(stderr, "failed to connect: command was: %d\n",
			ep->ehdr.commandID);
		return -1;
	}

	ep_keepalive(ep);
		
	return 0;
}

static int
create_data_sockets(struct ep *ep, const char *beamer)
{
	ep->video_fd = connect_to_host(SOCK_STREAM, beamer, "3621");
	if (ep->video_fd < 0)
		return -1;

	ep->audio_fd = connect_to_host(SOCK_STREAM, beamer, "3621");
	if (ep->audio_fd < 0)
		return -1;

	return 0;
}

static int
ep_read_ack(struct ep *ep)
{
	size_t len;

	init_iov(ep);

	len = readv(ep->ec_fd, ep->iov, 2);
	if (len < ep->iov[0].iov_len + ep->iov[1].iov_len) {
		fprintf(stderr, "error: command received is to short\n");
		return -1;
	}

	switch (ep->ehdr.commandID) {
	/* cack for connection video sockets */
	case E_CMD_22:
		break;
	case E_CMD_DISCONCLIENT:
		fprintf(stderr,
			"connection failed: probably incorrect version?\n");
		return -1;
	default:
		fprintf(stderr,
			"unexpected cmd: %d while waiting for socket ack.\n",
			ep->ehdr.commandID);
		return -1;
	}

	init_iov(ep);
	init_header(&ep->ehdr, E_CMD_REQCONNECT);

	set_ip(ep->ehdr.IPaddress, sock_get_ipv4_addr(ep->ec_fd));
	ep->ehdr.datasize = sizeof ep->ecmd;

	memset(&ep->ecmd, 0, sizeof ep->ecmd);

	ep->ehdr.commandID = 25;
	ep->ecmd.command.cmd25.unknown_field1 = 1;
	ep->ecmd.command.cmd25.unknown_field2 = 1;

	writev(ep->ec_fd, ep->iov, 1);

	return 0;
}

static int
ep_send_frame(struct ep *ep, char *buf, int size)
{
	struct econ_header hdr;
	memset(&hdr, 0, sizeof hdr);

	strncpy(hdr.magicnum, "EPRD", ECON_MAGICNUM_SIZE);
	strncpy(hdr.version,  "0600", ECON_PROTOVER_MAXLEN);

	hdr.commandID = 0;
	hdr.datasize = size;

	write(ep->video_fd, (void *) &hdr, sizeof hdr);
	write(ep->video_fd, buf, size);

	return 0;
}

static int
create_beamer_sockets(struct ep *ep, const char *beamer)
{
#if 0
	char myhostname[HOST_NAME_MAX+1];

	if (gethostname(myhostname, sizeof myhostname) < 0)
		return -1;

	/* Connection-procedure differes depending on udp or tcp:
	 * If reqconnect is done via udp:
	 *  Beamer tries to connet to 3620 on client
	 * If reqconnect is done via tcp:a
	 *  Beamer resuses tcp connection
	 */
	ep->ec_sfd = bind_socket(SOCK_STREAM, myhostname, STR(ECON_PORTNUMBER));
	if (ep->ec_sfd < 0)
		return -1;
#endif

	ep->ec_fd = connect_to_host(SOCK_STREAM, beamer, STR(ECON_PORTNUMBER));
	if (ep->ec_fd < 0)
		return -1;

	return 0;
}

int
main(int argc, char *argv[])
{
	struct ep ep;
	int len;
	const char *beamer;

	memset(&ep, 0, sizeof ep);

	if (argc < 2)
		exit(EXIT_FAILURE);

	beamer = argv[1];

	ep.vnc_mfd = bind_socket(SOCK_STREAM, "localhost", "5500");
	if (ep.vnc_mfd < 0)
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

	printf("w: %hu, h: %hu\n",
	       ntohs(init.msg.framebufferWidth),
	       ntohs(init.msg.framebufferHeight));

	/* values used by windows client */
	init.msg.format.depth = 32;
	init.msg.format.redShift = 0;
	init.msg.format.greenShift = 8;
	init.msg.format.blueShift = 16;

	/* copied from wireshark */
	init.msg.nameLength = htonl(3073);
	
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
	write(ep.vnc_fd, &framebuffer_update_request,
	      sizeof framebuffer_update_request);

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

	len = read(ep.vnc_fd, &framebuffer_update, sizeof framebuffer_update);
	printf("read framebuffer update?: %d\n", len);

	framebuffer_update.nrects = ntohs(framebuffer_update.nrects);
	printf("cmd: %d, nrects: %d\n", framebuffer_update.cmd,
	       ntohs(framebuffer_update.nrects));

	size_t bufsiz = (framebuffer_update.nrects *
			 (sizeof(struct rect) +
			  1024 * 768 * init.msg.format.bitsPerPixel/8));
	char *buf = malloc(bufsiz);
	assert(buf != NULL);

	len = loop_read(ep.vnc_fd, buf, bufsiz, 0);
	printf("read framebuffer update data?: %d\n", len);

	struct rect *rect = (void *) buf;
	printf("x: %d, y: %d, w: %d, h: %d, encoding: %d\n",
	       ntohs(rect->x), ntohs(rect->y),
	       ntohs(rect->w), ntohs(rect->h), ntohl(rect->encoding));

	FILE *img = fopen("/tmp/out.ppm", "w");
	write_ppm(img, 1024, 768, 4, rect->data);
	fclose(img);


	if (create_beamer_sockets(&ep, beamer) < 0)
		exit(EXIT_FAILURE);

	if (ep_get_clientinfo(&ep) < 0)
		exit(EXIT_FAILURE);

	if (ep_reqconnect(&ep, &init.msg) < 0)
		exit(EXIT_FAILURE);

	if (create_data_sockets(&ep, beamer) < 0)
		exit(EXIT_FAILURE);

	ep_keepalive(&ep);

	if (ep_read_ack(&ep) < 0)
		exit(EXIT_FAILURE);

	if (ep_send_frame(&ep, buf, bufsiz) < 0)
		exit(EXIT_FAILURE);

	while (1) {
		ep_keepalive(&ep);
		sleep(5);
	}

	pause();

	return 0;
}
