#include "config.h"

#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <pcap/pcap.h>

#define NMAP_ETHERNET_HEADER_LEN 14
#define NMAP_TCP_HEADER_MIN_LEN 20
#define NMAP_UDP_HEADER_LEN 8
#define NMAP_ICMP_HEADER_LEN 8

/**
 * @brief Return the layer 2 header length for the pcap datalink type.
 *
 * @param datalink Pcap datalink type.
 * @param offset Output offset to the IPv4 header.
 *
 * @return 1 on supported datalink, 0 otherwise.
 *
 * @note The current Docker/bridge setup returns DLT_EN10MB, which means
 *       Ethernet and therefore a 14-byte header before IPv4.
 */
static int	get_ip_offset(int datalink, size_t *offset)
{
	if (datalink == DLT_EN10MB)
	{
		*offset = NMAP_ETHERNET_HEADER_LEN;
		return (1);
	}
	return (0);
}

/**
 * @brief Read a big-endian uint16_t from a packet buffer.
 *
 * @param data Pointer to the 2-byte field.
 *
 * @return Host-order uint16_t value.
 */
static uint16_t	read_u16(const unsigned char *data)
{
	uint16_t	value;

	memcpy(&value, data, sizeof(value));
	return (ntohs(value));
}

/**
 * @brief Parse a direct TCP reply.
 *
 * @param ip IPv4 header of the captured packet.
 * @param packet Captured packet buffer.
 * @param len Captured packet length.
 * @param ip_offset Offset of the IPv4 header in the captured packet.
 * @param reply Output normalized reply.
 *
 * @return 1 on success, 0 if the packet is truncated.
 */
static int	parse_tcp_reply(const struct iphdr *ip, const unsigned char *packet,
		size_t len, size_t ip_offset, t_nmap_reply *reply)
{
	size_t				ip_header_len;
	size_t				tcp_offset;
	const unsigned char	*tcp;

	ip_header_len = (size_t)ip->ihl * 4;
	tcp_offset = ip_offset + ip_header_len;
	if (len < tcp_offset + NMAP_TCP_HEADER_MIN_LEN)
		return (0);
	tcp = packet + tcp_offset;
	reply->type = NMAP_REPLY_TCP;
	reply->src_ip = ip->saddr;
	reply->dst_ip = ip->daddr;
	reply->src_port = read_u16(tcp);
	reply->dst_port = read_u16(tcp + 2);
	reply->tcp_flags = tcp[13];
	return (1);
}

/**
 * @brief Parse a direct UDP reply.
 *
 * @param ip IPv4 header of the captured packet.
 * @param packet Captured packet buffer.
 * @param len Captured packet length.
 * @param ip_offset Offset of the IPv4 header in the captured packet.
 * @param reply Output normalized reply.
 *
 * @return 1 on success, 0 if the packet is truncated.
 */
static int	parse_udp_reply(const struct iphdr *ip, const unsigned char *packet,
		size_t len, size_t ip_offset, t_nmap_reply *reply)
{
	size_t				ip_header_len;
	size_t				udp_offset;
	const unsigned char	*udp;

	ip_header_len = (size_t)ip->ihl * 4;
	udp_offset = ip_offset + ip_header_len;
	if (len < udp_offset + NMAP_UDP_HEADER_LEN)
		return (0);
	udp = packet + udp_offset;
	reply->type = NMAP_REPLY_UDP;
	reply->src_ip = ip->saddr;
	reply->dst_ip = ip->daddr;
	reply->src_port = read_u16(udp);
	reply->dst_port = read_u16(udp + 2);
	return (1);
}

/**
 * @brief Parse the embedded TCP/UDP header inside an ICMP error.
 *
 * @param inner_ip Embedded original IPv4 header.
 * @param packet Captured packet buffer.
 * @param len Captured packet length.
 * @param inner_ip_offset Offset of the embedded IPv4 header.
 * @param reply Output normalized reply.
 *
 * @return 1 on success, 0 if the embedded packet is truncated or unsupported.
 */
static int	parse_icmp_original_transport(const struct iphdr *inner_ip,
		const unsigned char *packet, size_t len, size_t inner_ip_offset,
		t_nmap_reply *reply)
{
	size_t				inner_ip_len;
	size_t				transport_offset;
	const unsigned char	*transport;

	inner_ip_len = (size_t)inner_ip->ihl * 4;
	transport_offset = inner_ip_offset + inner_ip_len;
	reply->original_protocol = inner_ip->protocol;
	reply->original_src_ip = inner_ip->saddr;
	reply->original_dst_ip = inner_ip->daddr;
	if (inner_ip->protocol == IPPROTO_TCP)
	{
		if (len < transport_offset + NMAP_TCP_HEADER_MIN_LEN)
			return (0);
	}
	else if (inner_ip->protocol == IPPROTO_UDP)
	{
		if (len < transport_offset + NMAP_UDP_HEADER_LEN)
			return (0);
	}
	else
		return (0);
	transport = packet + transport_offset;
	reply->original_src_port = read_u16(transport);
	reply->original_dst_port = read_u16(transport + 2);
	return (1);
}

/**
 * @brief Parse an ICMP error reply.
 *
 * @param ip IPv4 header of the captured packet.
 * @param packet Captured packet buffer.
 * @param len Captured packet length.
 * @param ip_offset Offset of the IPv4 header in the captured packet.
 * @param reply Output normalized reply.
 *
 * @return 1 on success, 0 if the packet is truncated.
 *
 * @note ICMP errors contain the beginning of the original packet. That embedded
 *       packet is what allows matching the error with the original probe.
 */
static int	parse_icmp_reply(const struct iphdr *ip, const unsigned char *packet,
		size_t len, size_t ip_offset, t_nmap_reply *reply)
{
	size_t				ip_header_len;
	size_t				icmp_offset;
	size_t				inner_ip_offset;
	const unsigned char	*icmp;
	const struct iphdr	*inner_ip;

	ip_header_len = (size_t)ip->ihl * 4;
	icmp_offset = ip_offset + ip_header_len;
	if (len < icmp_offset + NMAP_ICMP_HEADER_LEN + sizeof(struct iphdr))
		return (0);
	icmp = packet + icmp_offset;
	inner_ip_offset = icmp_offset + NMAP_ICMP_HEADER_LEN;
	inner_ip = (const struct iphdr *)(packet + inner_ip_offset);
	if (inner_ip->version != 4 || inner_ip->ihl < 5)
		return (0);
	if (len < inner_ip_offset + ((size_t)inner_ip->ihl * 4))
		return (0);
	reply->type = NMAP_REPLY_ICMP;
	reply->src_ip = ip->saddr;
	reply->dst_ip = ip->daddr;
	reply->icmp_type = icmp[0];
	reply->icmp_code = icmp[1];
	return (parse_icmp_original_transport(inner_ip, packet, len,
			inner_ip_offset, reply));
}

/**
 * @brief Parse a raw pcap packet into a normalized reply.
 *
 * @param config Global nmap configuration.
 * @param packet Captured packet buffer.
 * @param len Captured packet length.
 * @param reply Output normalized reply.
 *
 * @return 1 when a supported reply was parsed, 0 otherwise.
 */
int	nmap_parse_pcap_packet(t_nmap_config *config, const unsigned char *packet,
		size_t len, t_nmap_reply *reply)
{
	size_t				ip_offset;
	const struct iphdr	*ip;
	size_t				ip_header_len;

	if (!config || !packet || !reply)
		return (0);
	memset(reply, 0, sizeof(*reply));
	if (!get_ip_offset(config->capture.datalink, &ip_offset))
		return (0);
	if (len < ip_offset + sizeof(struct iphdr))
		return (0);
	ip = (const struct iphdr *)(packet + ip_offset);
	if (ip->version != 4 || ip->ihl < 5)
		return (0);
	ip_header_len = (size_t)ip->ihl * 4;
	if (len < ip_offset + ip_header_len)
		return (0);
	if (ip->protocol == IPPROTO_TCP)
		return (parse_tcp_reply(ip, packet, len, ip_offset, reply));
	if (ip->protocol == IPPROTO_UDP)
		return (parse_udp_reply(ip, packet, len, ip_offset, reply));
	if (ip->protocol == IPPROTO_ICMP)
		return (parse_icmp_reply(ip, packet, len, ip_offset, reply));
	return (0);
}