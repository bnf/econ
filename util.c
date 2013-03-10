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
#include <string.h>
#include <assert.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <errno.h>

#include <poll.h>

#include "util.h"

uint32_t
sock_get_ipv4_addr(int fd)
{
	struct sockaddr_storage storage;
	struct sockaddr_in *own = (struct sockaddr_in *) &storage;
	socklen_t addrlen = sizeof(struct sockaddr_storage);

	assert(getsockname(fd, (struct sockaddr *) &storage, &addrlen) == 0);
	
	return own->sin_addr.s_addr;
}

static struct ifreq *
sock_get_ifreq(int fd)
{
	struct ifconf ifconf;
	static struct ifreq ifreqs[16];
	struct sockaddr_in *sin;
	uint32_t own_ip;
	int i;

	own_ip = sock_get_ipv4_addr(fd);

	ifconf.ifc_len = sizeof ifreqs;
	ifconf.ifc_req = ifreqs;
	if (ioctl(fd, SIOCGIFCONF, &ifconf) < 0) {
		fprintf(stderr, "retrieving interfaces failed: %s\n",
			strerror(errno));
		return NULL;
	}

	for (i = 0; i < ifconf.ifc_len/sizeof(ifreqs[0]); i++) {
		sin = (struct sockaddr_in *) &ifreqs[i].ifr_addr;

		if (sin->sin_addr.s_addr == own_ip)
			return &ifreqs[i];
	}

	return NULL;
}

uint32_t
sock_get_netmask(int fd)
{
	struct ifreq *ifreq;

	ifreq = sock_get_ifreq(fd);
	if (ifreq == NULL)
		return 0;
	
	if (ioctl(fd, SIOCGIFNETMASK, ifreq) < 0)
		return 0;
	
	return ((struct sockaddr_in *) &ifreq->ifr_netmask)->sin_addr.s_addr;
}

uint8_t *
sock_get_hwaddr(int fd)
{
	struct ifreq *ifreq;

	ifreq = sock_get_ifreq(fd);
	if (ifreq == NULL)
		return NULL;
	
	if (ioctl(fd, SIOCGIFHWADDR, ifreq) < 0)
		return NULL;
	if (ifreq->ifr_hwaddr.sa_family != ARPHRD_ETHER)
		return NULL;

	return (uint8_t *) &ifreq->ifr_hwaddr.sa_data[0];
}

uint32_t
sock_get_peer_ipv4_addr(int fd)
{
	struct sockaddr_storage storage;
	struct sockaddr_in *own = (struct sockaddr_in *) &storage;
	socklen_t addrlen = sizeof(struct sockaddr_storage);

	assert(getpeername(fd, (struct sockaddr *) &storage, &addrlen) == 0);
	
	return own->sin_addr.s_addr;
}

void
set_ip(uint8_t *ipbuf, uint32_t ip)
{
	ipbuf[0] = (ip & 0xFF);
	ipbuf[1] = (ip & 0xFF00) >> 8;
	ipbuf[2] = (ip & 0xFF0000) >> 16;
	ipbuf[3] = (ip & 0xFF000000) >> 24;
}


int
bind_socket(int socktype, const char *host, const char *port)
{
	struct addrinfo hints, *result, *rp;
	int reuseaddr = 1, s;
	int fd;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = socktype;

	printf("bind to host: %s, port: %s\n", host, port);

	s = getaddrinfo(host, port, &hints, &result);
	if (s != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
		return -1;
	}
	for (rp = result; rp != NULL; rp = rp->ai_next) {
		fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (fd == -1)
			continue;
		if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
			       &reuseaddr, sizeof(reuseaddr)) == -1)
			continue;

		/*ip = ((struct sockaddr_in *)rp->ai_addr)->sin_addr.s_addr;*/
		if (bind(fd, rp->ai_addr, rp->ai_addrlen) == 0)
			break;

		close(fd);
	}
	freeaddrinfo(result);
	if (rp == NULL) {
		fprintf(stderr, "Failed to bind: %s\n", strerror(errno));
		return -1;
	}

	if (socktype == SOCK_STREAM &&
	    listen(fd, 1) < 0) {
		fprintf(stderr, "Failed to listen: %s\n", strerror(errno));
		close(fd);
		return -1;
	}

	return fd;
}

int
connect_to_host(int socktype, const char *host, const char *port)
{
	struct addrinfo hints, *result, *rp;
	int fd, s;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = socktype;

	printf("connect to host: %s, port: %s\n", host, port);

	s = getaddrinfo(host, port, &hints, &result);
	if (s != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
		return -1;
	}
	for (rp = result; rp != NULL; rp = rp->ai_next) {
		fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (fd == -1)
			continue;

		if (connect(fd, rp->ai_addr, rp->ai_addrlen) != -1)
			break;

		close(fd);
	}
	freeaddrinfo(result);
	if (rp == NULL) {
		fprintf(stderr, "Failed to bind: %s\n", strerror(errno));
		return -1;
	}

	return fd;
}

/* From systemd:src/shared/util.c */
ssize_t
loop_read(int fd, void *buf, size_t nbytes, uint8_t do_poll)
{
        uint8_t *p;
        ssize_t n = 0;

        assert(fd >= 0);
        assert(buf);

        p = buf;

        while (nbytes > 0) {
                ssize_t k;

                if ((k = read(fd, p, nbytes)) <= 0) {

                        if (k < 0 && errno == EINTR)
                                continue;

                        if (k < 0 && errno == EAGAIN && do_poll) {
                                struct pollfd pollfd;

                                memset(&pollfd, 0, sizeof pollfd);
                                pollfd.fd = fd;
                                pollfd.events = POLLIN;

                                if (poll(&pollfd, 1, -1) < 0) {
                                        if (errno == EINTR)
                                                continue;

                                        return n > 0 ? n : -errno;
                                }

                                if (pollfd.revents != POLLIN)
                                        return n > 0 ? n : -EIO;

                                continue;
                        }

                        return n > 0 ? n : (k < 0 ? -errno : 0);
                }

                p += k;
                nbytes -= k;
                n += k;
        }

        return n;
}
