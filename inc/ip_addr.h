#ifndef NMAP_IP_ADDR_H
# define NMAP_IP_ADDR_H

# include <netinet/in.h>
# include <stddef.h>
# include <stdint.h>
# include <sys/socket.h>

# define NMAP_ADDR_TEXT_MAX 128

/**
 * @brief Protocol-independent IP address used by the scanner core.
 *
 * @note sockaddr_storage is intentionally kept at system-call boundaries.
 *       The runtime manipulates this smaller semantic type instead, so the
 *       scan engine never needs sockaddr_in/sockaddr_in6 casts.
 *
 * @note scope_id is meaningful for scoped IPv6 addresses such as link-local
 *       destinations. It is not part of the 128-bit address present on wire.
 */
typedef struct s_nmap_ip_addr
{
	sa_family_t	family;
	union
	{
		struct in_addr	v4;
		struct in6_addr	v6;
	} addr;
	uint32_t	scope_id;
}	t_nmap_ip_addr;

#endif
