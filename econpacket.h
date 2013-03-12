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
