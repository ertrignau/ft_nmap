#include "config.h"

#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>

#define TCP_FLAG_FIN 0x01
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_RST 0x04
#define TCP_FLAG_ACK 0x10

/**
 * @brief Check whether an ICMP unreachable code means filtered.
 *
 * @param code ICMP destination unreachable code.
 *
 * @return 1 if the code means filtered, 0 otherwise.
 */
static int	icmp_code_is_filtered(uint8_t code)
{
	return (code == ICMP_NET_UNREACH
		|| code == ICMP_HOST_UNREACH
		|| code == ICMP_PROT_UNREACH
		|| code == ICMP_NET_ANO
		|| code == ICMP_HOST_ANO
		|| code == ICMP_PKT_FILTERED);
}

/**
 * @brief Classify a TCP reply for a TCP scan.
 *
 * @param probe Probe matched with the reply.
 * @param reply Parsed reply.
 *
 * @return Scan result, or SCAN_RESULT_UNKNOWN when the reply is not useful.
 */
static t_scan_result	classify_tcp_reply(t_probe *probe, t_nmap_reply *reply)
{
	uint8_t	flags;

	flags = reply->tcp_flags;
	if (probe->scan_type == NMAP_SCAN_SYN)
	{
		if ((flags & TCP_FLAG_SYN) && (flags & TCP_FLAG_ACK))
			return (SCAN_RESULT_OPEN);
		if (flags & TCP_FLAG_RST)
			return (SCAN_RESULT_CLOSED);
	}
	else if (probe->scan_type == NMAP_SCAN_ACK)
	{
		if (flags & TCP_FLAG_RST)
			return (SCAN_RESULT_UNFILTERED);
	}
	else if (probe->scan_type == NMAP_SCAN_NULL
		|| probe->scan_type == NMAP_SCAN_FIN
		|| probe->scan_type == NMAP_SCAN_XMAS)
	{
		if (flags & TCP_FLAG_RST)
			return (SCAN_RESULT_CLOSED);
	}
	return (SCAN_RESULT_UNKNOWN);
}

/**
 * @brief Classify a UDP or ICMP reply for a UDP probe.
 *
 * @param reply Parsed reply.
 *
 * @return Scan result, or SCAN_RESULT_UNKNOWN when the reply is not useful.
 */
static t_scan_result	classify_udp_reply(t_nmap_reply *reply)
{
	if (reply->type == NMAP_REPLY_UDP)
		return (SCAN_RESULT_OPEN);
	if (reply->type == NMAP_REPLY_ICMP
		&& reply->icmp_type == ICMP_DEST_UNREACH)
	{
		if (reply->icmp_code == ICMP_PORT_UNREACH)
			return (SCAN_RESULT_CLOSED);
		if (icmp_code_is_filtered(reply->icmp_code))
			return (SCAN_RESULT_FILTERED);
	}
	return (SCAN_RESULT_UNKNOWN);
}

/**
 * @brief Classify an ICMP reply for a TCP probe.
 *
 * @param reply Parsed reply.
 *
 * @return Scan result, or SCAN_RESULT_UNKNOWN when the reply is not useful.
 */
static t_scan_result	classify_tcp_icmp_reply(t_nmap_reply *reply)
{
	if (reply->type == NMAP_REPLY_ICMP
		&& reply->icmp_type == ICMP_DEST_UNREACH
		&& icmp_code_is_filtered(reply->icmp_code))
		return (SCAN_RESULT_FILTERED);
	return (SCAN_RESULT_UNKNOWN);
}

/**
 * @brief Classify a matched reply for a probe.
 *
 * @param probe Probe matched with the reply.
 * @param reply Parsed reply.
 *
 * @return Final scan result, or SCAN_RESULT_UNKNOWN when the reply should be
 *         ignored.
 */
t_scan_result	nmap_classify_reply(t_probe *probe, t_nmap_reply *reply)
{
	if (!probe || !reply)
		return (SCAN_RESULT_UNKNOWN);
	if (probe->scan_type == NMAP_SCAN_UDP)
		return (classify_udp_reply(reply));
	if (reply->type == NMAP_REPLY_TCP)
		return (classify_tcp_reply(probe, reply));
	if (reply->type == NMAP_REPLY_ICMP)
		return (classify_tcp_icmp_reply(reply));
	return (SCAN_RESULT_UNKNOWN);
}