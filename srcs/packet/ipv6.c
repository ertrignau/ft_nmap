#include "packet/packet.h"

#include <arpa/inet.h>
#include <string.h>

/**
 * @brief IPv6 pseudo header used by TCP and UDP checksums.
 *
 * IPv6 has no checksum on its base IP header, but upper-layer checksums cover
 * the 128-bit source/destination addresses through this pseudo header.
 */
typedef struct __attribute__((packed)) s_ipv6_pseudo_header
{
	struct in6_addr	src;
	struct in6_addr	dst;
	uint32_t		length;
	uint8_t			zero[3];
	uint8_t			next_header;
}	t_ipv6_pseudo_header;

/**
 * @brief Fill the fixed 40-byte IPv6 base header for one transport probe.
 */
void	nmap_build_ipv6_header(t_nmap_target_ctx *ctx,
		t_nmap_ipv6_header *ip, uint8_t next_header, size_t payload_len)
{
	memset(ip, 0, sizeof(*ip));
	ip->version_tc_flow = htonl(6U << 28);
	ip->payload_length = htons((uint16_t)payload_len);
	ip->next_header = next_header;
	ip->hop_limit = (uint8_t)ctx->scan->ttl;
	ip->src = ctx->route.src_addr.addr.v6;
	ip->dst = ctx->target.addr.addr.v6;
}

/**
 * @brief Compute a TCP/UDP checksum using the IPv6 pseudo header.
 */
uint16_t	nmap_transport_checksum_ipv6(const t_nmap_target_ctx *ctx,
		uint8_t next_header, const void *transport, size_t len)
{
	t_ipv6_pseudo_header	pseudo;
	uint32_t				sum;

	memset(&pseudo, 0, sizeof(pseudo));
	pseudo.src = ctx->route.src_addr.addr.v6;
	pseudo.dst = ctx->target.addr.addr.v6;
	pseudo.length = htonl((uint32_t)len);
	pseudo.next_header = next_header;
	sum = nmap_checksum_add(0, &pseudo, sizeof(pseudo));
	sum = nmap_checksum_add(sum, transport, len);
	return (nmap_checksum_finish(sum));
}
