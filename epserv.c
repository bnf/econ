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
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/uio.h>
#include <unistd.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>

#include "econproto.h"
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
	int tcp_fd;
	int client_fd;
	int client_fd_data[2];

	int data_fd;
	char *host;

	unsigned char proj_uniq[ECON_UNIQINFO_LENGTH];
	enum e_proj_state state;

	struct iovec iov[3];
	struct econ_header ehdr;
	struct econ_command ecmd;
	struct econ_record erec;
	char *name;

	int data_index;
};

static void
get_hwaddr(struct ecs *ecs)
{
	struct ifreq ifreq;
	char *m = &ifreq.ifr_hwaddr.sa_data[0];

	memset(&ifreq, 0, sizeof ifreq);

	strcpy(ifreq.ifr_name, "tap0");
	ioctl(ecs->fd, SIOCGIFHWADDR, &ifreq);
	assert(ifreq.ifr_hwaddr.sa_family == ARPHRD_ETHER);
#if 0
	printf("hwaddr: %02hhx-%02hhx-%02hhx-%02hhx-%02hhx-%02hhx\n",
	       m[0], m[1], m[2], m[3], m[4], m[5]);
#endif

	memcpy(ecs->proj_uniq, m, 6);
}

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
handle_input(struct ecs *ecs, char *in, int fd,
	     struct sockaddr *src_addr, socklen_t addrlen)
{
	struct econ_header *hdr = (struct econ_header *) in;
	struct msghdr msg;

	memset(&msg, 0, sizeof msg);
	msg.msg_name = src_addr;
	msg.msg_namelen = addrlen;
	msg.msg_iov = ecs->iov;
	msg.msg_iovlen = ARRAY_SIZE(ecs->iov);

	switch (hdr->commandID) {
	case E_CMD_EASYSEARCH:
	case E_CMD_IPSEARCH:
		memset(&ecs->ecmd, 0, sizeof ecs->ecmd);
		ecs->ehdr.commandID = E_CMD_CLIENTINFO;
		/* Clientinfo needs a record or EasyMP crashes */
		ecs->ecmd.recordCount = 1;
		ecs->ehdr.datasize = (sizeof(struct econ_command) +
				      sizeof(struct econ_record));
		ecs->ecmd.command.clientinfo.projState = ecs->state;
		strncpy(ecs->ecmd.command.clientinfo.projName, ecs->name,
			ECON_PROJNAME_MAXLEN);
		ecs->ecmd.command.clientinfo.useKeyword = 0;
		ecs->ecmd.command.clientinfo.displayType = 0x07;

		sendmsg(fd, &msg, 0);

		struct e_cmd21 cmd21;
		ecs->ehdr.commandID = 21;
		ecs->ehdr.datasize = sizeof cmd21;
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
		iov[0].iov_base = &ecs->ehdr;
		iov[0].iov_len = sizeof ecs->ehdr;
		iov[1].iov_base = &cmd21;
		iov[1].iov_len = sizeof cmd21;
		msg.msg_iov = iov;
		msg.msg_iovlen = 2;

		sendmsg(fd, &msg, 0);
		break;
	case E_CMD_REQCONNECT:
		ecs->state = E_PSTAT_USING;
		memset(&ecs->ecmd, 0, sizeof ecs->ecmd);
		ecs->ehdr.commandID = E_CMD_CONNECTED;
		ecs->ecmd.recordCount = 1;
		ecs->ehdr.datasize = (sizeof(struct econ_command) +
				      sizeof(struct econ_record));
		ecs->ecmd.command.connected.projState = ecs->state;
		strncpy(ecs->ecmd.command.connected.projName, ecs->name,
			ECON_PROJNAME_MAXLEN);
		
		struct econ_command *rcmd =
			(struct econ_command *) (in + sizeof(struct econ_header));
		printf("reqconnect: width: %d, height: %d\n",
		       rcmd->command.reqconnect.vnesInitMsg.framebufferWidth,
		       rcmd->command.reqconnect.vnesInitMsg.framebufferHeight);

		//sendmsg(fd, &msg, 0);

		//ecs->ehdr.commandID = E_CMD_KEEPALIVE;

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
				fprintf(stderr, "failed to connect: %m\n");
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
		ecs->ehdr.commandID = E_CMD_FINISHRESTART;
		ecs->ehdr.datasize = 0;

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
	set_ip(ecs->ehdr.IPaddress, sock_get_peer_ipv4_addr(ecs->client_fd));

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
	set_ip(ecs->ehdr.IPaddress,
	       ((struct sockaddr_in *) &src_addr)->sin_addr.s_addr);

	if (n > 0)
		handle_input(ecs, in, ecs->udp_fd,
			     (struct sockaddr *) &src_addr, addrlen);
}

static void
init_iov(struct ecs *ecs)
{
	ecs->iov[0].iov_base = &ecs->ehdr;
	ecs->iov[0].iov_len = sizeof ecs->ehdr;
	ecs->iov[1].iov_base = &ecs->ecmd;
	ecs->iov[1].iov_len = sizeof ecs->ecmd;
	ecs->iov[2].iov_base = &ecs->erec;
	ecs->iov[2].iov_len = sizeof ecs->erec;
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
	init_iov(&ecs);
	init_header(&ecs.ehdr, E_CMD_CLIENTINFO);

	ecs.fd = bind_socket(SOCK_STREAM, host, control_port);
	assert(ecs.fd >= 0);
	get_hwaddr(&ecs);

	ecs.data_fd = bind_socket(SOCK_STREAM, host, video_port);
	assert(ecs.data_fd >= 0);

	ecs.udp_fd = bind_socket(SOCK_DGRAM, host, control_port);
	assert(ecs.udp_fd >= 0);

	ecs.tcp_fd = bind_socket(SOCK_DGRAM, host, control_port);
	listen(ecs.tcp_fd, 1);

	set_ip(ecs.erec.IPaddress, sock_get_ipv4_addr(ecs.fd));
	memcpy(ecs.erec.projUniqInfo, ecs.proj_uniq, 6);
	ecs.data_index = 0;

	while (1) {
		fd_set fds;
		int maxfd = MAX(ecs.fd, ecs.udp_fd);

		FD_ZERO(&fds);
		FD_SET(ecs.fd, &fds);
		FD_SET(ecs.data_fd, &fds);
		FD_SET(ecs.udp_fd, &fds);
		FD_SET(ecs.tcp_fd, &fds);
		maxfd = MAX(maxfd, ecs.tcp_fd);
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
			fprintf(stderr, "select failed: %m");
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
		if (FD_ISSET(ecs.tcp_fd, &fds)) {
			if (ecs.client_fd > 0)
				close(ecs.client_fd);
			ecs.client_fd = accept(ecs.tcp_fd, NULL, NULL);
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
				memset(&ecs.ecmd, 0, sizeof ecs.ecmd);
				ecs.ehdr.commandID = 22;
				ecs.ehdr.datasize = sizeof ecs.ecmd;
				ecs.ecmd.command.cmd22.unknown_field1 = 0x0000;
				ecs.ecmd.command.cmd22.unknown_field2 = 0x0000;
				ecs.ecmd.command.cmd22.width = 1024;
				ecs.ecmd.command.cmd22.height = 768;

				struct iovec iov[2];
				iov[0].iov_base = &ecs.ehdr;
				iov[0].iov_len = sizeof ecs.ehdr;
				iov[1].iov_base = &ecs.ecmd;
				iov[1].iov_len = sizeof ecs.ecmd;
				writev(ecs.client_fd, iov, 2);
			}
		}
	}

	close(ecs.fd);
	close(ecs.data_fd);
	close(ecs.udp_fd);
	close(ecs.tcp_fd);

	return 0;
}
