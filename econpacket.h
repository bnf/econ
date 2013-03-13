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

#ifndef _ECONPACKET_H_
#define _ECONPACKET_H_

#include <stddef.h>
#include <netinet/in.h>

#include "econproto.h"

struct econ_packet {
	struct econ_header hdr;
	struct econ_command cmd;
	struct econ_record rec;

	/* Storage for irregular long commands.
	 * This is just the remaining part, the first
	 * bytes are stored in cmd and rec. */
	char long_data[1024];
	size_t long_data_size;

	/* Holding the previous elements */
	struct iovec iov[4];

	/* For packets that are received via udp. */
	struct sockaddr_in addr;
};

void
epkt_init(struct econ_packet *pkt, int cmd);
int
epkt_send(int fd, struct econ_packet *pkt);
int
epkt_read(int fd, struct econ_packet *pkt);

#endif /* _ECONPACKET_H_ */
