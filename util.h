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

void
set_ip(uint8_t *ipbuf, uint32_t ip);
int
bind_socket(int socktype, const char *host, const char *port);
int
connect_to_host(int socktype, const char *host, const char *port);
ssize_t
loop_read(int fd, void *buf, size_t nbytes, uint8_t do_poll);

#endif /* _UTIL_H_ */
