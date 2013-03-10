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

#ifndef _UTIL_H_
#define _UTIL_H_

#include <stdint.h>

#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#define ARRAY_SIZE(arr) (sizeof (arr) / sizeof ((arr)[0]))

#define STR_EXPAND(tok) #tok
#define STR(str) STR_EXPAND(str)

uint32_t
sock_get_ipv4_addr(int fd);
uint32_t
sock_get_peer_ipv4_addr(int fd);
uint32_t
sock_get_netmask(int fd);
uint8_t *
sock_get_hwaddr(int fd);

void
set_ip(uint8_t *ipbuf, uint32_t ip);
int
bind_socket(int socktype, const char *host, const char *port);
int
connect_to_host(int socktype, const char *host, const char *port);
ssize_t
loop_read(int fd, void *buf, size_t nbytes, uint8_t do_poll);

#endif /* _UTIL_H_ */
