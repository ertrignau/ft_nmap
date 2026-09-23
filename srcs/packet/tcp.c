#include "packet/packet.h"
#include "debug/debug.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

/**
 * @brief Translate one TCP scan type into the exact outgoing TCP flags byte.
 */
static int	tcp_flags_for_scan(uint32_t scan_type, uint8_t *flags)
{
	if (scan_type == NMAP_SCAN_SYN)
		*flags = NMAP_TCP_SYN;
	else if (scan_type == NMAP_SCAN_NULL)
		*flags = 0;
	else if (scan_type == NMAP_SCAN_FIN)
		*flags = NMAP_TCP_FIN;
	else if (scan_type == NMAP_SCAN_XMAS)
		*flags = NMAP_TCP_FIN | NMAP_TCP_PSH | NMAP_TCP_URG;
	else if (scan_type == NMAP_SCAN_ACK)
		*flags = NMAP_TCP_ACK;
	else
	{
		return (0);
	}
	return (1);
}

/**
 * @brief Fill the protocol-independent TCP header for one logical probe.
 */
static int	build_tcp_header(const t_probe *probe, t_nmap_tcp_header *tcp)
{
	uint8_t	flags;

	if (!tcp_flags_for_scan(probe->scan_type, &flags))
		return (0);
	memset(tcp, 0, sizeof(*tcp));
	tcp->src_port = htons(probe->src_port);
	tcp->dst_port = htons(probe->dst_port);
	tcp->seq = htonl(probe->seq);
	tcp->data_offset = 5U << 4;
	tcp->flags = flags;
	tcp->window = htons(1024);
	return (1);
}

/**
 * @brief Build a complete raw IPv4 + TCP scan packet.
 */
static size_t	build_ipv4_tcp_packet(t_nmap_target_ctx *ctx, t_probe *probe,
		unsigned char *packet)
{
	t_nmap_ipv4_header	*ip;
	t_nmap_tcp_header	*tcp;

	ip = (t_nmap_ipv4_header *)packet;
	tcp = (t_nmap_tcp_header *)(packet + NMAP_IPV4_HEADER_LEN);
	if (!build_tcp_header(probe, tcp))
		return (0);
	tcp->checksum = nmap_transport_checksum_ipv4(ctx,
			IPPROTO_TCP, tcp, sizeof(*tcp));
	nmap_build_ipv4_header(ctx, probe, ip,
		IPPROTO_TCP, sizeof(*tcp));
	return (NMAP_IPV4_HEADER_LEN + sizeof(*tcp));
}

/**
 * @brief Build a complete raw IPv6 + TCP scan packet.
 */
static size_t	build_ipv6_tcp_packet(t_nmap_target_ctx *ctx, t_probe *probe,
		unsigned char *packet)
{
	t_nmap_ipv6_header	*ip;
	t_nmap_tcp_header	*tcp;

	ip = (t_nmap_ipv6_header *)packet;
	tcp = (t_nmap_tcp_header *)(packet + NMAP_IPV6_HEADER_LEN);
	if (!build_tcp_header(probe, tcp))
		return (0);
	tcp->checksum = nmap_transport_checksum_ipv6(ctx,
			IPPROTO_TCP, tcp, sizeof(*tcp));
	nmap_build_ipv6_header(ctx, ip, IPPROTO_TCP, sizeof(*tcp));
	return (NMAP_IPV6_HEADER_LEN + sizeof(*tcp));
}

/**
 * @brief Build and send one SYN/NULL/FIN/XMAS/ACK probe.
 */
int	nmap_send_tcp_probe(t_nmap_target_ctx *ctx, t_probe *probe)
{
	unsigned char	packet[NMAP_IPV6_HEADER_LEN + NMAP_TCP_HEADER_LEN];
	size_t			packet_len;
	uint64_t		prof_start;

	if (!ctx || !probe)
		return (0);
	memset(packet, 0, sizeof(packet));
	prof_start = PROF_START();
	if (ctx->target.addr.family == AF_INET)
		packet_len = build_ipv4_tcp_packet(ctx, probe, packet);
	else if (ctx->target.addr.family == AF_INET6)
		packet_len = build_ipv6_tcp_packet(ctx, probe, packet);
	else
	{
		packet_len = 0;
	}
	PROF_ADD(NMAP_PROF_SEND_BUILD, prof_start);
	if (packet_len == 0)
	{
		fprintf(stderr, "ft_nmap: cannot build TCP probe\n");
		return (0);
	}
	return (nmap_send_raw_packet(ctx, packet, packet_len));
}
