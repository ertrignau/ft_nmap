#include "packet/packet.h"
#include "debug/debug.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>

#define NMAP_ICMP_HEADER_LEN 8
#define NMAP_IPV6_FRAGMENT_HEADER_LEN 8

int	nmap_get_network_offset(int datalink, const unsigned char *packet,
		size_t len, size_t *offset, sa_family_t *family);

/** Read a network-order uint16_t from possibly unaligned packet bytes. */
static uint16_t	read_u16(const unsigned char *data)
{
	uint16_t	value;

	memcpy(&value, data, sizeof(value));
	return (ntohs(value));
}

/** Read a network-order uint32_t from possibly unaligned packet bytes. */
static uint32_t	read_u32(const unsigned char *data)
{
	uint32_t	value;

	memcpy(&value, data, sizeof(value));
	return (ntohl(value));
}

/** Normalize four packet bytes into a semantic IPv4 address. */
static void	set_ipv4_addr(t_nmap_ip_addr *addr, const unsigned char *bytes)
{
	memset(addr, 0, sizeof(*addr));
	addr->family = AF_INET;
	memcpy(&addr->addr.v4, bytes, sizeof(addr->addr.v4));
}

/** Normalize sixteen packet bytes into a semantic IPv6 address. */
static void	set_ipv6_addr(t_nmap_ip_addr *addr, const unsigned char *bytes)
{
	memset(addr, 0, sizeof(*addr));
	addr->family = AF_INET6;
	memcpy(&addr->addr.v6, bytes, sizeof(addr->addr.v6));
}

/**
 * @brief Parse the fields required from a direct TCP reply.
 */
static int	parse_tcp(const unsigned char *packet, size_t end,
		size_t offset, t_nmap_reply *reply)
{
	if (end < offset + NMAP_TCP_HEADER_LEN)
		return (0);
	reply->type = NMAP_REPLY_TCP;
	reply->src_port = read_u16(packet + offset);
	reply->dst_port = read_u16(packet + offset + 2);
	reply->tcp_seq = read_u32(packet + offset + 4);
	reply->tcp_ack = read_u32(packet + offset + 8);
	reply->tcp_flags = packet[offset + 13];
	return (1);
}

/**
 * @brief Parse the fields required from a direct UDP reply.
 */
static int	parse_udp(const unsigned char *packet, size_t end,
		size_t offset, t_nmap_reply *reply)
{
	if (end < offset + NMAP_UDP_HEADER_LEN)
		return (0);
	reply->type = NMAP_REPLY_UDP;
	reply->src_port = read_u16(packet + offset);
	reply->dst_port = read_u16(packet + offset + 2);
	return (1);
}

/**
 * @brief Parse the beginning of the original transport header quoted by ICMP.
 *
 * @note ICMP errors may quote only the beginning of the offending packet. TCP
 *       matching only requires ports and, when available here, the sequence
 *       number. A full 20-byte original TCP header is not required.
 */
static int	parse_original_transport(const unsigned char *packet,
		size_t end, size_t offset, uint8_t protocol, t_nmap_reply *reply)
{
	if (protocol == IPPROTO_TCP)
	{
		if (end < offset + 8)
			return (0);
		reply->original_src_port = read_u16(packet + offset);
		reply->original_dst_port = read_u16(packet + offset + 2);
		reply->original_tcp_seq = read_u32(packet + offset + 4);
		reply->has_original_tcp_seq = 1;
		return (1);
	}
	if (protocol == IPPROTO_UDP)
	{
		if (end < offset + NMAP_UDP_HEADER_LEN)
			return (0);
		reply->original_src_port = read_u16(packet + offset);
		reply->original_dst_port = read_u16(packet + offset + 2);
		return (1);
	}
	return (0);
}

/**
 * @brief Validate an IPv4 header and compute its captured logical bounds.
 *
 * @note Non-initial IPv4 fragments are ignored because they do not carry the
 *       transport header needed for reliable probe matching.
 */
static int	ipv4_bounds(const unsigned char *packet, size_t len,
		size_t ip_offset, size_t *header_len, size_t *end)
{
	uint16_t	total_len;
	uint16_t	fragment;

	if (len < ip_offset + NMAP_IPV4_HEADER_LEN
		|| (packet[ip_offset] >> 4) != 4)
		return (0);
	*header_len = (size_t)(packet[ip_offset] & 0x0f) * 4;
	if (*header_len < NMAP_IPV4_HEADER_LEN
		|| len < ip_offset + *header_len)
		return (0);
	total_len = read_u16(packet + ip_offset + 2);
	if (total_len < *header_len)
		return (0);
	*end = ip_offset + total_len;
	if (*end > len)
		*end = len;
	fragment = read_u16(packet + ip_offset + 6);
	if ((fragment & 0x1fffU) != 0)
		return (0);
	return (1);
}

/**
 * @brief Parse the original IPv4 packet embedded in an ICMPv4 error.
 */
static int	parse_original_ipv4(const unsigned char *packet,
		size_t len, size_t offset, t_nmap_reply *reply)
{
	size_t	header_len;
	size_t	end;
	uint8_t	protocol;

	if (!ipv4_bounds(packet, len, offset, &header_len, &end))
		return (0);
	protocol = packet[offset + 9];
	reply->original_protocol = protocol;
	set_ipv4_addr(&reply->original_src_addr, packet + offset + 12);
	set_ipv4_addr(&reply->original_dst_addr, packet + offset + 16);
	return (parse_original_transport(packet, end,
			offset + header_len, protocol, reply));
}

/**
 * @brief Parse an ICMPv4 error carrying an original IPv4 TCP/UDP probe.
 *
 * @note Only Destination Unreachable (3) and Time Exceeded (11) are useful to
 *       the current scan decision trees. Other ICMP types are ignored here.
 */
static int	parse_icmp4(const unsigned char *packet, size_t end,
		size_t offset, t_nmap_reply *reply)
{
	if (end < offset + NMAP_ICMP_HEADER_LEN + NMAP_IPV4_HEADER_LEN)
		return (0);
	reply->type = NMAP_REPLY_ICMP4;
	reply->icmp_type = packet[offset];
	reply->icmp_code = packet[offset + 1];
	if (reply->icmp_type != 3 && reply->icmp_type != 11)
		return (0);
	return (parse_original_ipv4(packet, end,
			offset + NMAP_ICMP_HEADER_LEN, reply));
}

/**
 * @brief Parse one captured IPv4 packet into t_nmap_reply.
 */
static int	parse_ipv4_packet(const unsigned char *packet,
		size_t len, size_t ip_offset, t_nmap_reply *reply)
{
	size_t	header_len;
	size_t	end;
	uint8_t	protocol;

	if (!ipv4_bounds(packet, len, ip_offset, &header_len, &end))
		return (0);
	set_ipv4_addr(&reply->src_addr, packet + ip_offset + 12);
	set_ipv4_addr(&reply->dst_addr, packet + ip_offset + 16);
	reply->hop_limit = packet[ip_offset + 8];
	protocol = packet[ip_offset + 9];
	if (protocol == IPPROTO_TCP)
		return (parse_tcp(packet, end, ip_offset + header_len, reply));
	if (protocol == IPPROTO_UDP)
		return (parse_udp(packet, end, ip_offset + header_len, reply));
	if (protocol == IPPROTO_ICMP)
		return (parse_icmp4(packet, end, ip_offset + header_len, reply));
	return (0);
}

/** Skip Hop-by-Hop/Routing/Destination Options extension headers. */
static int	ipv6_skip_options(const unsigned char *packet, size_t end,
		size_t *offset, uint8_t *next_header)
{
	size_t	header_len;

	if (end < *offset + 2)
		return (0);
	header_len = ((size_t)packet[*offset + 1] + 1) * 8;
	if (header_len < 8 || end < *offset + header_len)
		return (0);
	*next_header = packet[*offset];
	*offset += header_len;
	return (1);
}

/**
 * @brief Skip an IPv6 Fragment header when it is the first fragment.
 *
 * @note Non-zero fragment offsets cannot contain the beginning of TCP/UDP and
 *       therefore cannot be matched by this scanner without reassembly.
 */
static int	ipv6_skip_fragment(const unsigned char *packet, size_t end,
		size_t *offset, uint8_t *next_header)
{
	uint16_t	fragment;

	if (end < *offset + NMAP_IPV6_FRAGMENT_HEADER_LEN)
		return (0);
	fragment = read_u16(packet + *offset + 2);
	if ((fragment & 0xfff8U) != 0)
		return (0);
	*next_header = packet[*offset];
	*offset += NMAP_IPV6_FRAGMENT_HEADER_LEN;
	return (1);
}

/** Skip an IPv6 Authentication Header using its protocol-defined length. */
static int	ipv6_skip_ah(const unsigned char *packet, size_t end,
		size_t *offset, uint8_t *next_header)
{
	size_t	header_len;

	if (end < *offset + 2)
		return (0);
	header_len = ((size_t)packet[*offset + 1] + 2) * 4;
	if (header_len < 8 || end < *offset + header_len)
		return (0);
	*next_header = packet[*offset];
	*offset += header_len;
	return (1);
}

/**
 * @brief Walk the IPv6 Next Header chain until TCP, UDP or ICMPv6.
 *
 * @return 1 when a supported upper layer is found, 0 for malformed,
 *         unsupported or non-initial-fragment chains.
 */
static int	ipv6_find_upper(const unsigned char *packet, size_t end,
		size_t start, uint8_t first_header, size_t *upper_offset,
		uint8_t *upper_protocol)
{
	size_t	offset;
	uint8_t	next_header;

	offset = start;
	next_header = first_header;
	while (1)
	{
		if (next_header == IPPROTO_TCP || next_header == IPPROTO_UDP
			|| next_header == IPPROTO_ICMPV6)
		{
			*upper_offset = offset;
			*upper_protocol = next_header;
			return (1);
		}
		if (next_header == IPPROTO_HOPOPTS || next_header == IPPROTO_ROUTING
			|| next_header == IPPROTO_DSTOPTS)
		{
			if (!ipv6_skip_options(packet, end, &offset, &next_header))
				return (0);
		}
		else if (next_header == IPPROTO_FRAGMENT)
		{
			if (!ipv6_skip_fragment(packet, end, &offset, &next_header))
				return (0);
		}
		else if (next_header == IPPROTO_AH)
		{
			if (!ipv6_skip_ah(packet, end, &offset, &next_header))
				return (0);
		}
		else
		{
			return (0);
		}
	}
}

/** Validate an IPv6 base header and compute its captured logical end. */
static int	ipv6_bounds(const unsigned char *packet, size_t len,
		size_t ip_offset, size_t *end)
{
	uint16_t	payload_len;

	if (len < ip_offset + NMAP_IPV6_HEADER_LEN
		|| (packet[ip_offset] >> 4) != 6)
		return (0);
	payload_len = read_u16(packet + ip_offset + 4);
	*end = ip_offset + NMAP_IPV6_HEADER_LEN + payload_len;
	if (*end > len)
		*end = len;
	return (1);
}

/**
 * @brief Parse the original IPv6 packet embedded in an ICMPv6 error.
 */
static int	parse_original_ipv6(const unsigned char *packet,
		size_t len, size_t offset, t_nmap_reply *reply)
{
	size_t	end;
	size_t	upper_offset;
	uint8_t	protocol;

	if (!ipv6_bounds(packet, len, offset, &end))
		return (0);
	set_ipv6_addr(&reply->original_src_addr, packet + offset + 8);
	set_ipv6_addr(&reply->original_dst_addr, packet + offset + 24);
	if (!ipv6_find_upper(packet, end, offset + NMAP_IPV6_HEADER_LEN,
			packet[offset + 6], &upper_offset, &protocol))
		return (0);
	reply->original_protocol = protocol;
	return (parse_original_transport(packet, end,
			upper_offset, protocol, reply));
}

/**
 * @brief Parse an ICMPv6 error and its embedded original IPv6 probe.
 *
 * @note ICMPv6 error messages use types 1 through 4. Classification decides
 *       which type/code pairs are useful for a given scan.
 */
static int	parse_icmp6(const unsigned char *packet, size_t end,
		size_t offset, t_nmap_reply *reply)
{
	if (end < offset + NMAP_ICMP_HEADER_LEN + NMAP_IPV6_HEADER_LEN)
		return (0);
	reply->type = NMAP_REPLY_ICMP6;
	reply->icmp_type = packet[offset];
	reply->icmp_code = packet[offset + 1];
	if (reply->icmp_type < 1 || reply->icmp_type > 4)
		return (0);
	return (parse_original_ipv6(packet, end,
			offset + NMAP_ICMP_HEADER_LEN, reply));
}

/**
 * @brief Parse one captured IPv6 packet, including extension-header walking.
 */
static int	parse_ipv6_packet(const unsigned char *packet,
		size_t len, size_t ip_offset, t_nmap_reply *reply)
{
	size_t	end;
	size_t	upper_offset;
	uint8_t	protocol;

	if (!ipv6_bounds(packet, len, ip_offset, &end))
		return (0);
	set_ipv6_addr(&reply->src_addr, packet + ip_offset + 8);
	set_ipv6_addr(&reply->dst_addr, packet + ip_offset + 24);
	reply->hop_limit = packet[ip_offset + 7];
	if (!ipv6_find_upper(packet, end, ip_offset + NMAP_IPV6_HEADER_LEN,
			packet[ip_offset + 6], &upper_offset, &protocol))
		return (0);
	if (protocol == IPPROTO_TCP)
		return (parse_tcp(packet, end, upper_offset, reply));
	if (protocol == IPPROTO_UDP)
		return (parse_udp(packet, end, upper_offset, reply));
	if (protocol == IPPROTO_ICMPV6)
		return (parse_icmp6(packet, end, upper_offset, reply));
	return (0);
}

/**
 * @brief Parse one pcap frame into the common t_nmap_reply representation.
 *
 * @note Datalink location, IP-version parsing and runtime classification are
 *       deliberately separate layers. This function only normalizes wire data.
 */
int	nmap_parse_pcap_packet(t_nmap_config *config, const unsigned char *packet,
		size_t len, t_nmap_reply *reply)
{
	size_t		ip_offset;
	sa_family_t	family;
	uint64_t	prof_start;
	int			ret;

	if (!config || !packet || !reply)
		return (0);
	memset(reply, 0, sizeof(*reply));
	prof_start = PROF_START();
	if (!nmap_get_network_offset(config->capture.datalink,
			packet, len, &ip_offset, &family))
	{
		PROF_ADD(NMAP_PROF_LINK_OFFSET, prof_start);
		return (0);
	}
	PROF_ADD(NMAP_PROF_LINK_OFFSET, prof_start);
	prof_start = PROF_START();
	if (family == AF_INET)
	{
		ret = parse_ipv4_packet(packet, len, ip_offset, reply);
		PROF_ADD(NMAP_PROF_IPV4_PARSE, prof_start);
		return (ret);
	}
	if (family == AF_INET6)
	{
		ret = parse_ipv6_packet(packet, len, ip_offset, reply);
		PROF_ADD(NMAP_PROF_IPV6_PARSE, prof_start);
		return (ret);
	}
	return (0);
}
