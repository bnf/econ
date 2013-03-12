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
#include <errno.h>

#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "util.h"
#include "econproto.h"
#include "econpacket.h"

static int
connect_broadcast(const char *addr, int port)
{
	int fd, ret;
	struct sockaddr_in s;
	int broadcast_enable = 1;

	memset(&s, 0, sizeof s);
	s.sin_family = AF_INET;
	s.sin_port = htons(port);
	s.sin_addr.s_addr = inet_addr(addr);

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd == -1) 
		return -1;
	ret = setsockopt(fd, SOL_SOCKET, SO_BROADCAST,
			 &broadcast_enable, sizeof(broadcast_enable));
	if (ret < 0)
		exit(EXIT_FAILURE);
  
 
	if (connect(fd, (struct sockaddr *) &s, sizeof s) < 0) {
		fprintf(stderr, "Failed to connect: %s\n", strerror(errno));
		close(fd);
		return -1;
	}

	return fd;
}

int
main(int argc, char *argv[])
{
	int cfd, sfd;
	struct econ_packet pkt;
	struct in_addr in;
	const char *ip;

	if (argc < 2)
		exit(EXIT_FAILURE);


	cfd = connect_broadcast(argv[1], ECON_PORTNUMBER);
	if (cfd < 0)
		exit(EXIT_FAILURE);

	in.s_addr = sock_get_ipv4_addr(cfd);
	ip = inet_ntoa(in);
	fprintf(stderr, "own ip: %s\n", inet_ntoa(in));
	sfd = bind_socket(SOCK_DGRAM, ip, STR(ECON_PORTNUMBER));

	epkt_init(&pkt, E_CMD_EASYSEARCH);
	if (epkt_send(cfd, &pkt) < 0)
		exit(EXIT_FAILURE);

	if (epkt_read(sfd, &pkt) < 0)
		exit(EXIT_FAILURE);

	if (pkt.hdr.commandID == E_CMD_CLIENTINFO) {
		struct in_addr beamer;
		
		beamer.s_addr = *(uint32_t*)pkt.hdr.IPaddress;
		printf("%s", inet_ntoa(beamer));
		if (pkt.hdr.datasize > 0) {
			char *name = pkt.cmd.command.clientinfo.projName;
			int state = pkt.cmd.command.clientinfo.projState;

			name[ECON_PROJNAME_MAXLEN-1] = '\0';
			printf(" - %s: %s", name,
			       state == E_PSTAT_NOUSE ? "no use" : "in use");
		}
		printf("\n");
	}

	return 0;
}
