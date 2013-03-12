#ifndef _ECONPACKET_H_
#define _ECONPACKET_H_

#include "econproto.h"

struct econ_packet {
	struct econ_header hdr;
	struct econ_command cmd;
	struct econ_record rec;

	/* Holding the previous elements */
	struct iovec iov[3];
};

void
epkt_init(struct econ_packet *pkt, int cmd);
int
epkt_send(int fd, struct econ_packet *pkt);
int
epkt_read(int fd, struct econ_packet *pkt);

#endif /* _ECONPACKET_H_ */
