#include <stdio.h>
#include <string.h>

#include <unistd.h>
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

int
epkt_read(int fd, struct econ_packet *pkt)
{
	union { ssize_t s; size_t u; } len;

	init_iov(pkt);

	len.s = readv(fd, pkt->iov, 3);
	if (len.s < 0)
		return -1;

	if (len.u < sizeof(struct econ_header)) {
		fprintf(stderr, "epkt_read: error: incomplete header\n");
		return -1;
	}

	if (len.u < sizeof(struct econ_header) + pkt->hdr.datasize) {
		fprintf(stderr, "packet has invalid datasize\n");
		return -1;
	}

	if (pkt->hdr.datasize > 0) {
		if (pkt->hdr.datasize < sizeof(struct econ_command)) {
			fprintf(stderr,
				"epkt_read: error: command to short\n");
			return -1;
		}

		/* Keepalive is an irregular if datasize > 0:
		 *  the regular field recordCount is 1,
		 *  without actually having one. */
		if (pkt->hdr.commandID == E_CMD_KEEPALIVE)
			return 0;

		if (pkt->cmd.recordCount > 0) {
			if (pkt->cmd.recordCount > 1) {
				fprintf(stderr, "epkt_read:"
					" did not expect a packet with more"
					" that one record: %d, datasize: %d.\n",
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
	}

	return 0;
}
