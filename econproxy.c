/*
 * Copyright © 2013 Benjamin Franzke
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
#include <arpa/inet.h>

#if 0
#include <limits.h>
#endif

#include "econproto.h"
#include "econpacket.h"
#include "util.h"

struct ep {
	int vnc_mfd;
	int vnc_fd;

	int ec_fd;
	int ec_sfd;

	int video_fd;
	int audio_fd;

	struct econ_packet epkt;

	uint8_t projUniqInfo[ECON_UNIQINFO_LENGTH];	
	rfbServerInitMsg vnesInitMsg;
};

struct rfb_framebuffer_update {
	uint8_t cmd;
	uint8_t padding;
	uint16_t nrects;
};

struct rfb_frame {
	uint16_t x, y;
	uint16_t width, height;
	int32_t encoding;
#if 0
	uint8_t data[0];
#endif
};


static void
init_packet(struct ep *ep, int commandID)
{
	epkt_init(&ep->epkt, commandID);
	set_ip(ep->epkt.hdr.IPaddress, sock_get_ipv4_addr(ep->ec_fd));
}

static int
ep_keepalive(struct ep *ep)
{
	init_packet(ep, E_CMD_KEEPALIVE);
	if (epkt_send(ep->ec_fd, &ep->epkt) < 0)
		return -1;

	return 0;
}

static int
ep_get_clientinfo(struct ep *ep)
{
	init_packet(ep, E_CMD_IPSEARCH);
	epkt_send(ep->ec_fd, &ep->epkt);

	if (epkt_read(ep->ec_fd, &ep->epkt) < 0)
		return -1;
	if (ep->epkt.hdr.commandID != E_CMD_CLIENTINFO) {
		fprintf(stderr, "expected clientinfo, got: %d\n",
			ep->epkt.hdr.commandID);
		return -1;
	}

	if (ep->epkt.hdr.datasize == 0 || ep->epkt.cmd.recordCount == 0) {
		fprintf(stderr, "missing record in clientinfo\n");
		return -1;
	}

	printf("clientinfo unknown value: %hu\n",
	       ep->epkt.cmd.command.clientinfo.unknown_field_1);
	/* cache projUniqInfo needed for reqconnect */
	memcpy(ep->projUniqInfo, ep->epkt.rec.projUniqInfo, ECON_UNIQINFO_LENGTH);

	if (epkt_read(ep->ec_fd, &ep->epkt) < 0)
		return -1;

	if (ep->epkt.hdr.commandID != 21) {
		fprintf(stderr, "expected ex clientinfo (21), got: %d\n",
			ep->epkt.hdr.commandID);
		return -1;
	}

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
ep_reqconnect(struct ep *ep)
{
	init_packet(ep, E_CMD_REQCONNECT);
	ep->epkt.hdr.datasize = sizeof ep->epkt.cmd + sizeof ep->epkt.rec;

	vnes_ntoh(&ep->vnesInitMsg, &ep->epkt.cmd.command.reqconnect.vnesInitMsg);

	set_ip(ep->epkt.cmd.command.reqconnect.subnetMask,
	       sock_get_netmask(ep->ec_fd));
#if 1
	/* FIXME: need to set gateway address? */
	ep->epkt.cmd.command.reqconnect.gateAddress[0] = 192;
	ep->epkt.cmd.command.reqconnect.gateAddress[1] = 168;
	ep->epkt.cmd.command.reqconnect.gateAddress[2] = 1;
	ep->epkt.cmd.command.reqconnect.gateAddress[3] = 1;
#endif

	/* The first two seem to be ignored, 0x00, works as well as 0xff.
	 * Windows client uses 0x02 and 0x01, so we do too. */
	ep->epkt.cmd.command.reqconnect.unknown_field_1 = 0x02;
	ep->epkt.cmd.command.reqconnect.unknown_field_2 = 0x01;
	ep->epkt.cmd.command.reqconnect.unknown_field_3 = 0x03;
#if 0
	memcpy(ep->epkt.cmd.command.reqconnect.EncPassword, "82091965",
	       ECON_ENCRYPTION_MAXLEN);
#endif

	ep->epkt.cmd.recordCount = 1;
	set_ip(ep->epkt.rec.IPaddress, sock_get_peer_ipv4_addr(ep->ec_fd));
	memcpy(ep->epkt.rec.projUniqInfo, ep->projUniqInfo, ECON_UNIQINFO_LENGTH);

	epkt_send(ep->ec_fd, &ep->epkt);

	if (epkt_read(ep->ec_fd, &ep->epkt) < 0)
		return -1;
	if (ep->epkt.hdr.commandID != E_CMD_CONNECTED) {
		fprintf(stderr, "failed to connect: command was: %d\n",
			ep->epkt.hdr.commandID);
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
	if (epkt_read(ep->ec_fd, &ep->epkt) < 0)
		return -1;

	switch (ep->epkt.hdr.commandID) {
	/* cack for connection video sockets */
	case E_CMD_22:
		break;
	case E_CMD_DISCONCLIENT:
		fprintf(stderr,
			"connection failed: probably incorrect version?\n");
		return -1;
	case E_CMD_KEEPALIVE:
		return ep_read_ack(ep);
	default:
		fprintf(stderr,
			"unexpected cmd: %d while waiting for socket ack.\n",
			ep->epkt.hdr.commandID);
		return -1;
	}

	if (ep->epkt.hdr.datasize == 0) {
		fprintf(stderr, "error: command 22 received is to short\n");
		return -1;
	}

	init_packet(ep, E_CMD_25);
	ep->epkt.hdr.datasize = sizeof ep->epkt.cmd;
	ep->epkt.cmd.command.cmd25.unknown_field1 = 1;
	ep->epkt.cmd.command.cmd25.unknown_field2 = 1;

	epkt_send(ep->ec_fd, &ep->epkt);

	return 0;
}

static int
ep_send_frames(struct ep *ep, struct iovec *iov, int iovcnt, uint32_t datasize)
{
	struct econ_header hdr;
	memset(&hdr, 0, sizeof hdr);

	strncpy(hdr.magicnum, "EPRD", ECON_MAGICNUM_SIZE);
	strncpy(hdr.version,  "0600", ECON_PROTOVER_MAXLEN);
	set_ip(hdr.IPaddress, sock_get_ipv4_addr(ep->video_fd));

	hdr.commandID = 0;
	hdr.datasize = htonl(datasize);

	write(ep->video_fd, (void *) &hdr, sizeof hdr);
	writev(ep->video_fd, iov, iovcnt);

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

static int
rfb_framebuffer_update_request(struct ep *ep, int incremental)
{
	struct {
		uint8_t cmd;
		uint8_t incremental;
		uint16_t x, y, w, h;
	} framebuffer_update_request = {
		3, 0,
		htons(0), htons(0), htons(1024), htons(768)
	};

	framebuffer_update_request.incremental = incremental;

	return write(ep->vnc_fd, &framebuffer_update_request,
		     sizeof framebuffer_update_request);
}

static void
free_iov(struct iovec *iov, int iovcnt, int members_only)
{
	int i;

	for (i = 0; i < iovcnt; ++i) {
		if (iov[i].iov_base == NULL)
			break;
		free(iov[i].iov_base);
	}
	if (!members_only)
		free(iov);
}

static int
rfb_retrieve_framebuffer_update(struct ep *ep,
				struct iovec **piov, int *iovcnt,
				uint32_t *psize)
{
	struct rfb_framebuffer_update *framebuffer_update;
	int i;
	struct iovec *iov;
	ssize_t len;
	uint32_t datasize = 0;

	framebuffer_update = malloc(sizeof *framebuffer_update);
	if (framebuffer_update == NULL)
		return -1;
	len = read(ep->vnc_fd, framebuffer_update, sizeof *framebuffer_update);
	if (len < 0) {
		free(framebuffer_update);
		return -1;
	}

	printf("read framebuffer update?: %zd\n", len);

	/* The Epson Beamer Protocol also stores it in host order,
	 * so make this permanent. */
	framebuffer_update->nrects = ntohs(framebuffer_update->nrects);
	printf("nrects: %d\n", framebuffer_update->nrects);

	if (framebuffer_update->nrects == 0) {
		fprintf(stderr, "error: invalid number of rects\n");
		free(framebuffer_update);
		return -1;
	}

	iov = calloc(1 + 2 * framebuffer_update->nrects, sizeof *iov);
	if (iov == NULL) {
		free(framebuffer_update);
		return -1;
	}

	iov[0].iov_base = framebuffer_update;
	iov[0].iov_len = sizeof *framebuffer_update;
	datasize += sizeof *framebuffer_update;
	iov++;

	for (i = 0; i < framebuffer_update->nrects; ++i) {
		char *data;
		size_t size;
		off_t offset = 0;
		ssize_t r;
		struct rfb_frame *frame = malloc(sizeof *frame);

		if (frame == NULL)
			goto err;

		iov[i*2+0].iov_base = frame;
		iov[i*2+0].iov_len = sizeof *frame;
		datasize += sizeof *frame;

		r = readv(ep->vnc_fd, &iov[i*2+0], 1);
		printf("r: %zd\n", r);

		if (ntohs(frame->width) == 0 || ntohs(frame->height) == 0)
			goto err;
		
		printf("encoding: %u\n", ntohl(frame->encoding));
		switch (ntohl(frame->encoding)) {
		case 0: /* RAW */
			size = (ntohs(frame->width) * ntohs(frame->height)) * 32/8;
			data = malloc(size);
			if (data == NULL)
				goto err;
			break;
#if 0
		/* FIXME: doesnt work yet */
		case 7: /* TIGHT */
		{
			uint8_t compression_control;
			uint8_t compact_len[3];
			const size_t bs = sizeof(uint8_t);
			uint8_t count = 1;
			uint32_t len;

			read(ep->vnc_fd, &compression_control,
			     sizeof compression_control);
			printf("compression control: %x\n", compression_control);
#if 0
			/* jpeg compression has 0x90, others we cannot handle */
			if (!(compression_control & 0x90))
				goto err;
#endif

			read(ep->vnc_fd, &compact_len[0], bs);
			len = compact_len[0] & 0x7F;
			if (compact_len[0] & 0x80) {
				read(ep->vnc_fd, &compact_len[1], bs);
				len |= (compact_len[1] & 0x7F) << 7;
				count = 2;
				if (compact_len[1] & 0x80) {
					read(ep->vnc_fd, &compact_len[2], bs);
					len |= (compact_len[2] & 0xFF) << 14;
					count = 3;
				}
			}
			offset = (sizeof compression_control +
				  count * sizeof(compact_len[0]));
			size = offset + len;
			data = malloc(size);
			if (data == NULL)
				goto err;
			data[0] = compression_control;
			memcpy(&data[1], compact_len,
			       count * sizeof(compact_len[0]));

		}
			break;
#endif
#if 1
		/* seems to be not supported */
		case 16: /* ZRLE */
		case 6: /* Zlib */
		{
			uint32_t length;
			if (read(ep->vnc_fd, &length, sizeof length) < 0)
				goto err;

			length = ntohl(length);
			offset = sizeof length;
			size = offset + length;

			data = malloc(size);
			if (data == NULL)
				goto err;

			*((uint32_t *) data) = htonl(length);
		}
			break;
#endif
#if 1
		case 2: /* RRE */
		{
			uint32_t subrects;
			if (read(ep->vnc_fd, &subrects, sizeof subrects) < 0)
				goto err;

			subrects = ntohl(subrects);
			offset = sizeof subrects;

			size = offset + 4 + subrects * (4 + 8);
			data = malloc(size);
			if (data == NULL)
				goto err;

			*((uint32_t *) data) = htonl(subrects);
		}
			break;
#endif
		default:
			goto err;
		}

		printf("size for %dx%d: %zd\n",
		       ntohs(frame->width), ntohs(frame->height), size);

		iov[i*2+1].iov_base = data;
		iov[i*2+1].iov_len = size;
		datasize += size;

		len = loop_read(ep->vnc_fd, &data[offset], size-offset, 0);
		if (len < 0 || (size_t) len != (size-offset))
			goto err;

	}

	iov--;
	*piov = iov;
	*iovcnt = 1 + i * 2;
	*psize = datasize;

	framebuffer_update->nrects = htons(framebuffer_update->nrects);

	return 0;

err:
	free_iov(--iov, 1 + framebuffer_update->nrects * 2, 0);

	return -1;
}

static int
rfb_init(struct ep *ep, const char *vnc_server_ip, const char *vnc_server_port)
{
	char client_protocol[12];
	const char *rfb_protocol = "RFB 003.008\n";
	char security_types[BUFSIZ];
#define NOAUTH 1
	uint8_t auth = NOAUTH;
	uint32_t auth_result = 0;
	uint8_t share_desktop = 1;
	struct iovec iov[2];
	union init {
		rfbServerInitMsg msg;
		struct {
			rfbServerInitMsg msg;
#if 0
			char name[0];
#endif
		} d;
		char buf[BUFSIZ];
	} init;
	ssize_t len;

	if (vnc_server_ip) {
		ep->vnc_mfd = -1;
		ep->vnc_fd = connect_to_host(SOCK_STREAM,
					     vnc_server_ip, vnc_server_port);
		if (ep->vnc_fd < 0)
			return -1;
	} else {
		ep->vnc_mfd = bind_socket(SOCK_STREAM, "localhost", "5500");
		if (ep->vnc_mfd < 0)
			return -1;

		ep->vnc_fd = accept(ep->vnc_mfd, NULL, NULL);
		if (ep->vnc_fd < 0)
			return -1;
	}

	read(ep->vnc_fd, client_protocol, sizeof client_protocol);

	write(ep->vnc_fd, rfb_protocol, strlen(rfb_protocol));

	len = read(ep->vnc_fd, security_types, BUFSIZ);
	printf("security_types: %zd\n", len);

	if (write(ep->vnc_fd, &auth, sizeof auth) < 0)
		return -1;

	len = read(ep->vnc_fd, &auth_result, sizeof auth_result);
	if (len < 0)
		return -1;
	if (auth_result != 0) {
		fprintf(stderr, "auth failed: %d, %zd\n", auth_result, len);
		return -1;
	}

	if (write(ep->vnc_fd, &share_desktop, sizeof share_desktop) < 0)
		return -1;
	
	len = read(ep->vnc_fd, &init, sizeof init);
	printf("read init: %zd\n", len);
	if (len < 0)
		return -1;

	printf("w: %hu, h: %hu\n",
	       ntohs(init.msg.framebufferWidth),
	       ntohs(init.msg.framebufferHeight));

#if 0
	/* values used by windows client */
	init.msg.format.depth = 32;
	init.msg.format.redShift = 0;
	init.msg.format.greenShift = 8;
	init.msg.format.blueShift = 16;

	/* copied from wireshark */
	init.msg.nameLength = htonl(3073);
#endif
	
	struct {
		uint8_t cmd;
		uint8_t padding1;
		uint16_t padding2;
	} cmd_set_pixel_format = { 0, 0, 0 };

	iov[0].iov_base = &cmd_set_pixel_format;
	iov[0].iov_len = sizeof cmd_set_pixel_format;
	iov[1].iov_base = &init.msg.format;
	iov[1].iov_len = sizeof init.msg.format;

	if (writev(ep->vnc_fd, iov, 2) < 0)
		return -1;

	struct {
		uint8_t cmd;
		uint8_t padding;
		uint16_t number_of_encodings;
		uint32_t encodings[5];
	} cmd_set_encodings = {
		2, 0, htons(5),
#if 1
		{ htonl(0) /* RAW */, htonl(7) /* Tight */, htonl(6) /* Zlib */, htonl(16) /* ZRLE */, htonl(2) /* RRE */ }
#else
		{ htonl(6) /* Zlib */, htonl(2) /* RRE */, htonl(7) /* Tight */, htonl(16) /* ZRLE */, htonl(0) /* RAW */ }
#endif
	};

	if (write(ep->vnc_fd, &cmd_set_encodings, sizeof cmd_set_encodings) < 0)
		return -1;

	ep->vnesInitMsg = init.msg;

	return 0;
}

static int
econ_init(struct ep *ep, const char *beamer)
{
	if (create_beamer_sockets(ep, beamer) < 0)
		return -1;

	if (ep_get_clientinfo(ep) < 0)
		return -1;

	if (ep_reqconnect(ep) < 0)
		return -1;

	if (create_data_sockets(ep, beamer) < 0)
		return -1;

	ep_keepalive(ep);

	if (ep_read_ack(ep) < 0)
		return -1;

	return 0;
}

int
main(int argc, char *argv[])
{
	struct ep ep;
	const char *beamer;
	const char *vnc_server_ip = NULL, *vnc_server_port = "5900";
	int incremental = 0;
	int ch;

	memset(&ep, 0, sizeof ep);

	opterr = 0;
	while ((ch = getopt(argc, argv, "v:p:")) != -1) {
		switch (ch) {
		case 'v':
			vnc_server_ip = optarg;
			break;
		case 'p':
			vnc_server_port = optarg;
			break;
		default:
			exit(EXIT_FAILURE);
		}
	}
	argc -= optind;
	argv += optind;

	if (argc < 1)
		exit(EXIT_FAILURE);

	beamer = argv[0];
	
	if (rfb_init(&ep, vnc_server_ip, vnc_server_port) < 0)
		exit(EXIT_FAILURE);

	if (econ_init(&ep, beamer) < 0)
		exit(EXIT_FAILURE);

	while (1) {
		struct iovec *iov;
		int iovcnt;
		uint32_t datasize;

		ep_keepalive(&ep);
		rfb_framebuffer_update_request(&ep, incremental);
		if (rfb_retrieve_framebuffer_update(&ep, &iov, &iovcnt,
						&datasize) == 0) {
			if (ep_send_frames(&ep, iov, iovcnt, datasize) < 0)
				exit(EXIT_FAILURE);
			free_iov(iov, iovcnt, 0);
			/* actually needed only once */
			incremental = 1;
		}
		/*usleep(15 * 1000ULL);*/
	}

	return 0;
}
