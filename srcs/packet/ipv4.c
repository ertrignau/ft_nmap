#include "packet/packet.h"

#include <arpa/inet.h>
#include <string.h>

/**
 * @brief IPv4 pseudo header used by TCP and UDP checksums.
 */
typedef struct __attribute__((packed)) s_ipv4_pseudo_header
{
	struct in_addr	src;
	struct in_addr	dst;
	uint8_t			zero;
	uint8_t			protocol;
	uint16_t		length;
}	t_ipv4_pseudo_header;

/**
 * @brief Fill the IPv4 header surrounding one transport probe.
 *
 * @param config Current target/route state.
 * @param probe Logical probe used to derive a stable identification value.
 * @param ip Destination wire header.
 * @param protocol Upper-layer protocol (TCP/UDP).
 * @param payload_len Upper-layer byte length.
 */
void	nmap_build_ipv4_header(t_nmap_config *config, t_probe *probe,
		t_nmap_ipv4_header *ip, uint8_t protocol, size_t payload_len)
{
	memset(ip, 0, sizeof(*ip));
	ip->version_ihl = 0x45;
	ip->total_length = htons((uint16_t)(NMAP_IPV4_HEADER_LEN + payload_len));
	ip->identification = htons(probe->src_port);
	ip->ttl = (uint8_t)config->scan.ttl;
	ip->protocol = protocol;
	ip->src = config->route.src_addr.addr.v4;
	ip->dst = config->target.addr.addr.v4;
	ip->checksum = nmap_checksum(ip, sizeof(*ip));
}

/**
 * @brief Compute a TCP/UDP checksum using the IPv4 pseudo header.
 */
uint16_t	nmap_transport_checksum_ipv4(const t_nmap_config *config,
		uint8_t protocol, const void *transport, size_t len)
{
	t_ipv4_pseudo_header	pseudo;
	uint32_t				sum;

	memset(&pseudo, 0, sizeof(pseudo));
	pseudo.src = config->route.src_addr.addr.v4;
	pseudo.dst = config->target.addr.addr.v4;
	pseudo.protocol = protocol;
	pseudo.length = htons((uint16_t)len);
	sum = nmap_checksum_add(0, &pseudo, sizeof(pseudo));
	sum = nmap_checksum_add(sum, transport, len);
	return (nmap_checksum_finish(sum));
}
