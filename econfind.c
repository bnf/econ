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

#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "util.h"
#include "econproto.h"
#include "econpacket.h"

static void
parse_clientinfo(struct econ_packet *pkt)
{
	/* Clientinfo has our ip in the packet header,
	 * and the record has the ip 16.0.32.0,
	 * none of them are the acutal beamer ip,
	 * so we retreive that from the up packet directly. */
	printf("%s", inet_ntoa(pkt->addr.sin_addr));

	if (pkt->hdr.datasize > 0) {
		char *name = pkt->cmd.command.clientinfo.projName;
		int state = pkt->cmd.command.clientinfo.projState;

		name[ECON_PROJNAME_MAXLEN-1] = '\0';
		printf(" - %s: %s", name,
		       state == E_PSTAT_NOUSE ? "no use" : "in use");
	}
	printf("\n");
}

int
main(int argc, char *argv[])
{
	int cfd, sfd;
	struct econ_packet pkt;
	struct in_addr in;

	if (argc < 2)
		exit(EXIT_FAILURE);

	cfd = connect_to_host(SOCK_DGRAM, argv[1], STR(ECON_PORTNUMBER));
	if (cfd < 0)
		exit(EXIT_FAILURE);

	in.s_addr = sock_get_ipv4_addr(cfd);
	sfd = bind_socket(SOCK_DGRAM, inet_ntoa(in), STR(ECON_PORTNUMBER));

	epkt_init(&pkt, E_CMD_EASYSEARCH);
	set_ip(pkt.hdr.IPaddress, sock_get_ipv4_addr(sfd));

	if (epkt_send(cfd, &pkt) < 0)
		exit(EXIT_FAILURE);

	if (epkt_read(sfd, &pkt) < 0)
		exit(EXIT_FAILURE);

	if (pkt.hdr.commandID == E_CMD_CLIENTINFO)
		parse_clientinfo(&pkt);

	if (epkt_read(sfd, &pkt) < 0)
		exit(EXIT_FAILURE);

	close(cfd);
	close(sfd);

	return 0;
}
