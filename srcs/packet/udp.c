#include "packet/packet.h"
#include "debug/debug.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

/**
 * @brief Fill the generic empty UDP datagram header.
 *
 * @note Protocol-specific UDP payload profiles can later be appended without
 *       changing scheduler/thread ownership.
 */
static void	build_udp_header(const t_probe *probe, t_nmap_udp_header *udp)
{
	memset(udp, 0, sizeof(*udp));
	udp->src_port = htons(probe->src_port);
	udp->dst_port = htons(probe->dst_port);
	udp->length = htons(sizeof(*udp));
}

/**
 * @brief Build a complete raw IPv4 + UDP probe.
 */
static size_t	build_ipv4_udp_packet(t_nmap_config *config, t_probe *probe,
		unsigned char *packet)
{
	t_nmap_ipv4_header	*ip;
	t_nmap_udp_header	*udp;

	ip = (t_nmap_ipv4_header *)packet;
	udp = (t_nmap_udp_header *)(packet + NMAP_IPV4_HEADER_LEN);
	build_udp_header(probe, udp);
	udp->checksum = nmap_transport_checksum_ipv4(config,
			IPPROTO_UDP, udp, sizeof(*udp));
	if (udp->checksum == 0)
		udp->checksum = 0xffff;
	nmap_build_ipv4_header(config, probe, ip,
		IPPROTO_UDP, sizeof(*udp));
	return (NMAP_IPV4_HEADER_LEN + sizeof(*udp));
}

/**
 * @brief Build a complete raw IPv6 + UDP probe.
 *
 * @note UDP checksums are mandatory for normal IPv6 UDP traffic, so the
 *       pseudo-header checksum is always generated here.
 */
static size_t	build_ipv6_udp_packet(t_nmap_config *config, t_probe *probe,
		unsigned char *packet)
{
	t_nmap_ipv6_header	*ip;
	t_nmap_udp_header	*udp;

	ip = (t_nmap_ipv6_header *)packet;
	udp = (t_nmap_udp_header *)(packet + NMAP_IPV6_HEADER_LEN);
	build_udp_header(probe, udp);
	udp->checksum = nmap_transport_checksum_ipv6(config,
			IPPROTO_UDP, udp, sizeof(*udp));
	if (udp->checksum == 0)
		udp->checksum = 0xffff;
	nmap_build_ipv6_header(config, ip, IPPROTO_UDP, sizeof(*udp));
	return (NMAP_IPV6_HEADER_LEN + sizeof(*udp));
}

/**
 * @brief Build and send one generic UDP probe.
 */
int	nmap_send_udp_probe(t_nmap_config *config, t_probe *probe)
{
	unsigned char	packet[NMAP_IPV6_HEADER_LEN + NMAP_UDP_HEADER_LEN];
	size_t			packet_len;
	uint64_t		prof_start;

	if (!config || !probe)
		return (0);
	memset(packet, 0, sizeof(packet));
	prof_start = PROF_START();
	if (config->target.addr.family == AF_INET)
		packet_len = build_ipv4_udp_packet(config, probe, packet);
	else if (config->target.addr.family == AF_INET6)
		packet_len = build_ipv6_udp_packet(config, probe, packet);
	else
		packet_len = 0;
	PROF_ADD(NMAP_PROF_SEND_BUILD, prof_start);
	if (packet_len == 0)
	{
		fprintf(stderr, "ft_nmap: cannot build UDP probe\n");
		return (0);
	}
	return (nmap_send_raw_packet(config, packet, packet_len));
}
