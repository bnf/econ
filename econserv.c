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

#if 0
#define _POSIX_C_SOURCE 200112L
#define _BSD_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/uio.h>
#include <unistd.h>
#include <netinet/in.h>

#include "econproto.h"
#include "econpacket.h"
#include "util.h"

struct e_cmd21 {
	char projUniqInfo[6];
	uint8_t zero_padding1[20];
	uint8_t unknown_data1_20[20];

	/* width_1 and width_2 should be equal,
	 * or EasyMP uses 800, same applies for height. */
	uint16_t width_1;
	uint16_t height_1;

	uint8_t unknown_data2_6[6];

	uint16_t width_2;
	uint16_t height_2;

	uint8_t unknown_data3_112[112];
	uint8_t zero_padding2[366];
};

static uint8_t cmd21_unknown_data1[20] = {
0x00, 0x95, 0x00, 0x00,
0x01, 0x04, 0x09, 0x00, 0x00, 0x00, 0x02, 0x06,
0x50, 0x42, 0x30, 0x30, 0x00, 0x00, 0x03, 0x06,
};

static uint8_t cmd21_unknown_data2[6] = {
0x00, 0x00, 0x04, 0x06, 0x02, 0x00,
};

static uint8_t cmd21_unknown_data3[112] = {
0x05, 0x58,
0x07, 0x09, 0x08, 0x00, 0x00, 0x00, 0x10, 0x00,
0x10, 0x00, 0x20, 0x00, 0x20, 0x00, 0x90, 0x02,
0xa0, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07, 0x0b,
0x08, 0x00, 0x00, 0x00, 0x08, 0x00, 0x08, 0x00,
0x10, 0x00, 0x10, 0x00, 0x90, 0x02, 0xa0, 0x01,
0x00, 0x00, 0x00, 0x00, 0x07, 0x0d, 0x08, 0x00,
0x00, 0x00, 0x08, 0x00, 0x08, 0x00, 0x10, 0x00,
0x10, 0x00, 0x90, 0x02, 0xa0, 0x01, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
0x08, 0x00, 0x08, 0x00, 0x10, 0x00, 0x10, 0x00,
0x90, 0x02, 0xa0, 0x01, 0x00, 0x00, 0x00, 0x00,
                                    /* audio=0x07 */
0x06, 0x04, 0x00, 0x00, 0x00, 0x00, 0x07, 0x0a,
           /* namelength */
0x01, 0x00, 0x01, 0x0c, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x08, 0x08, 0x1f, 0x03,
};


struct ecs {
	int fd;
	int udp_fd;
	int client_fd;
	int client_fd_data[2];

	int data_fd;
	char *host;

	unsigned char proj_uniq[ECON_UNIQINFO_LENGTH];
	enum e_proj_state state;

	struct econ_packet epkt;
	char *name;

	int data_index;
};

static void
get_hwaddr(struct ecs *ecs)
{
	uint8_t *m;

	m = sock_get_hwaddr(ecs->fd);
	assert(m != NULL);

	memcpy(ecs->proj_uniq, m, 6);
}

static void
handle_input(struct ecs *ecs, char *in, int fd,
	     struct sockaddr *src_addr, socklen_t addrlen)
{
	struct econ_header *hdr = (struct econ_header *) in;
	struct msghdr msg;

	memset(&msg, 0, sizeof msg);
	msg.msg_name = src_addr;
	msg.msg_namelen = addrlen;
	msg.msg_iov = ecs->epkt.iov;
	msg.msg_iovlen = 3;

	fprintf(stderr, "handle_input: %d, udp: %s\n",
		hdr->commandID, src_addr ? "yes" : "no");

	switch (hdr->commandID) {
	case E_CMD_EASYSEARCH:
	case E_CMD_IPSEARCH:
#if 1
		if (msg.msg_name) {
			((struct sockaddr_in *) msg.msg_name)->sin_port =
				htons(ECON_PORTNUMBER);
		}
#endif
		memset(&ecs->epkt.cmd, 0, sizeof ecs->epkt.cmd);
		ecs->epkt.hdr.commandID = E_CMD_CLIENTINFO;
		/* Clientinfo needs a record or EasyMP crashes */
		ecs->epkt.cmd.recordCount = 1;
		ecs->epkt.hdr.datasize = (sizeof(struct econ_command) +
				      sizeof(struct econ_record));
		ecs->epkt.cmd.command.clientinfo.projState = ecs->state;
		strncpy(ecs->epkt.cmd.command.clientinfo.projName, ecs->name,
			ECON_PROJNAME_MAXLEN);
		ecs->epkt.cmd.command.clientinfo.useKeyword = 0;
		ecs->epkt.cmd.command.clientinfo.displayType = 0x07;

		sendmsg(fd, &msg, 0);

		struct e_cmd21 cmd21;
		ecs->epkt.hdr.commandID = 21;
		ecs->epkt.hdr.datasize = sizeof cmd21;
		memset(&cmd21, 0, sizeof cmd21);
		memcpy(&cmd21.projUniqInfo, ecs->proj_uniq, 6);
		memcpy(cmd21.unknown_data1_20, cmd21_unknown_data1,
		       sizeof cmd21_unknown_data1);
		memcpy(cmd21.unknown_data2_6, cmd21_unknown_data2,
		       sizeof cmd21_unknown_data2);
		memcpy(cmd21.unknown_data3_112, cmd21_unknown_data3,
		       sizeof cmd21_unknown_data3);

		cmd21.width_1 = cmd21.width_2 = 1024;
		cmd21.height_1 = cmd21.height_2 = 768;

		struct iovec iov[2];
		iov[0].iov_base = &ecs->epkt.hdr;
		iov[0].iov_len = sizeof ecs->epkt.hdr;
		iov[1].iov_base = &cmd21;
		iov[1].iov_len = sizeof cmd21;
		msg.msg_iov = iov;
		msg.msg_iovlen = 2;

		sendmsg(fd, &msg, 0);
		break;
	case E_CMD_REQCONNECT:
		ecs->state = E_PSTAT_USING;
		memset(&ecs->epkt.cmd, 0, sizeof ecs->epkt.cmd);
		ecs->epkt.hdr.commandID = E_CMD_CONNECTED;
		ecs->epkt.cmd.recordCount = 1;
		ecs->epkt.hdr.datasize = (sizeof(struct econ_command) +
				      sizeof(struct econ_record));
		ecs->epkt.cmd.command.connected.projState = ecs->state;
		strncpy(ecs->epkt.cmd.command.connected.projName, ecs->name,
			ECON_PROJNAME_MAXLEN);
		
		struct econ_command *rcmd =
			(struct econ_command *) (in + sizeof(struct econ_header));
		printf("reqconnect: width: %d, height: %d\n",
		       rcmd->command.reqconnect.vnesInitMsg.framebufferWidth,
		       rcmd->command.reqconnect.vnesInitMsg.framebufferHeight);

#if 0
		sendmsg(fd, &msg, 0);
#endif

#if 0
		ecs->epkt.hdr.commandID = E_CMD_KEEPALIVE;
#endif

		if (addrlen > 0) {
			if (ecs->client_fd >= 0)
				close(ecs->client_fd);
			ecs->client_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
			if (ecs->client_fd == -1)
				exit(3);
			struct sockaddr_in in;
			
			in.sin_family = AF_INET;
			in.sin_port = htons(ECON_PORTNUMBER);
			in.sin_addr.s_addr = ((struct sockaddr_in *) src_addr)->sin_addr.s_addr;
			printf("got connect request\n");
			if (connect(ecs->client_fd, (struct sockaddr *) &in, sizeof in) != 0) {
				perror("Failed to connect");
				close(ecs->client_fd);
				ecs->client_fd = -1;
				ecs->state = E_PSTAT_NOUSE;
				return;
			}
		}

		sendmsg(ecs->client_fd, &msg, 0);
		break;
	case E_CMD_KEEPALIVE:
		printf("keepalive: src_addr: %p\n", (void *) src_addr);
		break;
	case E_CMD_REQRESTART:
		printf("request restart = stop?\n");
		ecs->state = E_PSTAT_NOUSE;
		ecs->epkt.hdr.commandID = E_CMD_FINISHRESTART;
		ecs->epkt.hdr.datasize = 0;

		msg.msg_iovlen = 1;
		sendmsg(ecs->client_fd, &msg, 0);
		if (ecs->client_fd >= 0)
			close(ecs->client_fd);
		ecs->client_fd = -1;
		if (ecs->client_fd_data[0] >= 0)
			close(ecs->client_fd_data[0]);
		if (ecs->client_fd_data[1] >= 0)
			close(ecs->client_fd_data[1]);
		ecs->client_fd_data[0] = ecs->client_fd_data[1] = -1;
		ecs->data_index = 0;
		break;
	case 25:
		printf("got cmdid 25 = seems to be not an ack for cmd22.. but what else?\n");
		break;
	default:
		printf("Unhandled command: %d\n", hdr->commandID);
		break;
	}
}

static void
recv_tcp(struct ecs *ecs)
{
	char in[BUFSIZ];
	int n;

	n = recv(ecs->client_fd, in, BUFSIZ, 0);
	if (n == 0) {
		close(ecs->client_fd);
		ecs->client_fd = -1;
		return;
	}

	printf("n tcp: %d\n", n);
	set_ip(ecs->epkt.hdr.IPaddress, sock_get_peer_ipv4_addr(ecs->client_fd));

	if (n > 0)
		handle_input(ecs, in, ecs->client_fd, NULL, 0);
}

static void
recv_udp(struct ecs *ecs)
{
	struct sockaddr_storage src_addr;
	socklen_t addrlen = sizeof(struct sockaddr_storage);
	char in[BUFSIZ];
	int n;

	n = recvfrom(ecs->udp_fd, in, BUFSIZ, 0,
		     (struct sockaddr *) &src_addr, &addrlen);
	printf("n udp: %d\n", n);
	set_ip(ecs->epkt.hdr.IPaddress,
	       ((struct sockaddr_in *) &src_addr)->sin_addr.s_addr);

	if (n > 0)
		handle_input(ecs, in, ecs->udp_fd,
			     (struct sockaddr *) &src_addr, addrlen);
}

int main(int argc, char *argv[])
{
	struct ecs ecs;
	char *host = NULL;
	char *control_port = STR(ECON_PORTNUMBER);
	char *video_port = "3621";

	memset(&ecs, 0, sizeof ecs);

	if (argc < 2)
		return 1;

	host = argv[1];

	ecs.name = "benp";
	ecs.client_fd =	ecs.client_fd_data[0] = ecs.client_fd_data[1] = -1;
	ecs.state = E_PSTAT_NOUSE;
	epkt_init(&ecs.epkt, E_CMD_CLIENTINFO);

	ecs.fd = bind_socket(SOCK_STREAM, host, control_port);
	assert(ecs.fd >= 0);
	get_hwaddr(&ecs);

	ecs.data_fd = bind_socket(SOCK_STREAM, host, video_port);
	assert(ecs.data_fd >= 0);

	ecs.udp_fd = bind_socket(SOCK_DGRAM, "0.0.0.0", control_port);
	assert(ecs.udp_fd >= 0);

	set_ip(ecs.epkt.rec.IPaddress, sock_get_ipv4_addr(ecs.fd));
	memcpy(ecs.epkt.rec.projUniqInfo, ecs.proj_uniq, 6);
	ecs.data_index = 0;

	while (1) {
		fd_set fds;
		int maxfd = MAX(ecs.fd, ecs.udp_fd);

		FD_ZERO(&fds);
		FD_SET(ecs.fd, &fds);
		FD_SET(ecs.data_fd, &fds);
		FD_SET(ecs.udp_fd, &fds);
		maxfd = MAX(maxfd, ecs.udp_fd);
		if (ecs.client_fd >= 0) {
			FD_SET(ecs.client_fd, &fds);
			maxfd = MAX(maxfd, ecs.client_fd);
		}
		if (ecs.client_fd_data[0] >= 0) {
			FD_SET(ecs.client_fd_data[0], &fds);
			maxfd = MAX(maxfd, ecs.client_fd_data[0]);
		}
		if (ecs.client_fd_data[1] >= 0) {
			FD_SET(ecs.client_fd_data[1], &fds);
			maxfd = MAX(maxfd, ecs.client_fd_data[1]);
		}

		if (select(maxfd + 1, &fds, NULL, NULL, NULL) <= 0) {
			perror("Select failed");
			continue;
		}

		if (FD_ISSET(ecs.client_fd, &fds)) {
			recv_tcp(&ecs);
		}
		if (FD_ISSET(ecs.fd, &fds)) {
			if (ecs.client_fd >= 0)
				close(ecs.client_fd);
			ecs.client_fd = accept(ecs.fd, NULL, NULL);
		}
		if (FD_ISSET(ecs.udp_fd, &fds)) {
			recv_udp(&ecs);
		}

		if (FD_ISSET(ecs.data_fd, &fds)) {
			if (ecs.data_index == 2) {
				printf("to many data conns, closing old\n");
				close(ecs.client_fd_data[0]);
				close(ecs.client_fd_data[1]);
				ecs.data_index = 0;
			}

			ecs.client_fd_data[ecs.data_index++] = accept(ecs.data_fd, NULL, NULL);
			printf("got data con\n");

			if (ecs.data_index == 2) {
				memset(&ecs.epkt.cmd, 0, sizeof ecs.epkt.cmd);
				ecs.epkt.hdr.commandID = 22;
				ecs.epkt.hdr.datasize = sizeof ecs.epkt.cmd;
				ecs.epkt.cmd.command.cmd22.unknown_field1 = 0x0000;
				ecs.epkt.cmd.command.cmd22.unknown_field2 = 0x0000;
				ecs.epkt.cmd.command.cmd22.width = 1024;
				ecs.epkt.cmd.command.cmd22.height = 768;

				struct iovec iov[2];
				iov[0].iov_base = &ecs.epkt.hdr;
				iov[0].iov_len = sizeof ecs.epkt.hdr;
				iov[1].iov_base = &ecs.epkt.cmd;
				iov[1].iov_len = sizeof ecs.epkt.cmd;
				writev(ecs.client_fd, iov, 2);
			}
		}
	}

	close(ecs.fd);
	close(ecs.data_fd);
	close(ecs.udp_fd);

	return 0;
}
