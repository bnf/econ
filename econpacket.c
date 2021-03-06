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

#include <unistd.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include "econpacket.h"
#include "econproto.h"

static void
init_iov(struct econ_packet *pkt)
{
	pkt->iov[0].iov_base = &pkt->hdr;
	pkt->iov[0].iov_len = sizeof pkt->hdr;
	pkt->iov[1].iov_base = &pkt->cmd;
	pkt->iov[1].iov_len = sizeof pkt->cmd;
	pkt->iov[2].iov_base = &pkt->rec;
	pkt->iov[2].iov_len = sizeof pkt->rec;

	/* To receive oversized commands */
	pkt->iov[3].iov_base = pkt->long_data;
	pkt->iov[3].iov_len = sizeof pkt->long_data;
}

static void
init_header(struct econ_header *ehdr, int cmd)
{
	memset(ehdr, 0, sizeof *ehdr);

	strncpy(ehdr->magicnum, ECON_MAGIC_NUMBER,  ECON_MAGICNUM_SIZE);
	strncpy(ehdr->version,  ECON_PROTO_VERSION, ECON_PROTOVER_MAXLEN);

	ehdr->datasize = 0;
	ehdr->commandID = cmd;
}

void
epkt_init(struct econ_packet *pkt, int cmd)
{
	init_iov(pkt);

	memset(&pkt->rec, 0, sizeof pkt->rec);
	memset(&pkt->cmd, 0, sizeof pkt->cmd);
	init_header(&pkt->hdr, cmd);

	/* For irregular commands like 21 */
	pkt->long_data_size = 0;
}

int
epkt_send(int fd, struct econ_packet *pkt)
{
	int i = 1;

	if (pkt->hdr.datasize > 0) {
		i++;
		if (pkt->cmd.recordCount == 1)
			i++;
	}

	return writev(fd, pkt->iov, i);
}

static int
iov_max_read(struct iovec *iov, size_t *iovcnt, size_t size)
{
	size_t i;

	for (i = 0; i < *iovcnt; ++i) {
		if (iov[i].iov_len > size) {
			iov[i].iov_len = size;
			*iovcnt = i+1;
			return 0;
		}
		size -= iov[i].iov_len;
	}

	if (size > 0)
		return -1;

	return 0;
}

int
epkt_read(int fd, struct econ_packet *pkt)
{
	union { ssize_t s; size_t u; } len, len2;
	int type;
	socklen_t length = sizeof(int);
	struct msghdr msg;

	memset(&msg, 0, sizeof msg);
	init_iov(pkt);
	msg.msg_iov = pkt->iov;
	pkt->long_data_size = 0;

	if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &length) < 0)
		return -1;

	/* FIXME Do we get the diffs between udp and tcp handled a bit nicer? */
	switch (type) {
	case SOCK_STREAM:
		msg.msg_iovlen = 1;
		break;
	case SOCK_DGRAM:
		msg.msg_iovlen = 4;
		msg.msg_name = &pkt->addr;
		msg.msg_namelen = sizeof pkt->addr;
		break;
	default:
		return -1;
	}

	len.s = recvmsg(fd, &msg, 0);
	if (len.s < 0)
		return -1;

	if (len.u < sizeof(struct econ_header)) {
		fprintf(stderr, "epkt_read: error: incomplete header\n");
		return -1;
	}

	fprintf(stderr, "epkt_read: len.u: %zd, cmd: %d, datasize: %d\n",
		len.u, pkt->hdr.commandID, pkt->hdr.datasize);

	if (pkt->hdr.datasize == 0) {
		if (len.u > sizeof(struct econ_header))
		    return -1;
		return 0;
	}

	if (pkt->hdr.datasize > 1024)
		return -1;

	if (type == SOCK_STREAM) {
		msg.msg_iovlen = 3;
		msg.msg_iov = &pkt->iov[1];
		if (iov_max_read(msg.msg_iov, &msg.msg_iovlen,
				 pkt->hdr.datasize) < 0)
			return -1;

		/* Yes, this may write up to long_data[1024]. */
		len2.s = recvmsg(fd, &msg, 0);
		if (len2.s < 0 || len2.u != pkt->hdr.datasize)
			return -1;

		len.u += len2.u;
	}

	if (len.u != sizeof(struct econ_header) + pkt->hdr.datasize) {
		fprintf(stderr, "packet has invalid datasize\n");
		return -1;
	}

	if (pkt->hdr.datasize < sizeof(struct econ_command)) {
		fprintf(stderr,
			"epkt_read: error: command to short\n");
		return -1;
	}

	/* Keepalive is an irregular command if datasize > 0:
	 *  the regular field recordCount is 1,
	 *  without actually having one. */
	if (pkt->hdr.commandID == E_CMD_KEEPALIVE)
		return 0;

	/* Handle irregular long datasize */
	if (pkt->hdr.datasize > (sizeof(struct econ_command) +
				 sizeof(struct econ_record))) {
		switch (pkt->hdr.commandID) {
		case E_CMD_21:
			break;
		default:
			fprintf(stderr, "epkt_read: received cmd: %d"
				" with oversized datasize\n",
				pkt->hdr.commandID);
			exit(EXIT_FAILURE);
		}
		pkt->long_data_size = (pkt->hdr.datasize -
				       (sizeof (struct econ_command) +
					sizeof (struct econ_record)));
		return 0;
	}

	if (pkt->cmd.recordCount > 0) {
		if (pkt->cmd.recordCount > 1) {
			fprintf(stderr, "epkt_read: did not expect a packet "
				"with more than one record: %d, datasize: %d.\n",
				pkt->cmd.recordCount, pkt->hdr.datasize);
			return -1;
		}
		if (pkt->hdr.datasize != (sizeof (struct econ_command) +
					  sizeof (struct econ_record))) {
			fprintf(stderr, "epkt_read: datasize incorrect, cmd: %d\n",
				pkt->hdr.commandID);
			return -1;
		}
	}

	return 0;
}
