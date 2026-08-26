#ifndef NMAP_NET_ADDRESS_H
# define NMAP_NET_ADDRESS_H

# include "ip_addr.h"

/** Convert a system sockaddr representation into the scanner IP type. */
int	nmap_ip_from_sockaddr(t_nmap_ip_addr *dst,
		const struct sockaddr *src, socklen_t src_len);

/** Convert the scanner IP type to a sockaddr suitable for socket APIs. */
int	nmap_ip_to_sockaddr(const t_nmap_ip_addr *src, uint16_t port,
		struct sockaddr_storage *dst, socklen_t *dst_len);

/** Compare only the IP address/family present on wire (not IPv6 scope_id). */
int	nmap_ip_equal(const t_nmap_ip_addr *a, const t_nmap_ip_addr *b);

/** Render one IPv4/IPv6 address to text. */
int	nmap_ip_ntop(const t_nmap_ip_addr *addr, char *dst, size_t dst_size);

#endif
