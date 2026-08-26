#include "runtime/runtime_internal.h"
#include "net/address.h"
#include "packet/wire.h"

/**
 * @brief Return whether an ICMPv4 Destination Unreachable code participates in
 *        the scan decision trees.
 */
static int	icmp4_unreachable_code_is_known(uint8_t code)
{
	return (code == 0 || code == 1 || code == 2 || code == 3
		|| code == 9 || code == 10 || code == 13);
}

/**
 * @brief Classify a matched direct TCP response according to scan type.
 */
static t_scan_result	classify_tcp_packet(const t_probe *probe,
		const t_nmap_reply *reply)
{
	uint8_t	flags;

	flags = reply->tcp_flags;
	if (probe->scan_type == NMAP_SCAN_SYN)
	{
		if ((flags & NMAP_TCP_SYN) && (flags & NMAP_TCP_ACK))
			return (SCAN_RESULT_OPEN);
		if (flags & NMAP_TCP_RST)
			return (SCAN_RESULT_CLOSED);
		/* Split-handshake behavior: a matching SYN is evidence of OPEN. */
		if (flags & NMAP_TCP_SYN)
			return (SCAN_RESULT_OPEN);
	}
	else if (probe->scan_type == NMAP_SCAN_ACK)
	{
		if (flags & NMAP_TCP_RST)
			return (SCAN_RESULT_UNFILTERED);
	}
	else if (probe->scan_type == NMAP_SCAN_NULL
		|| probe->scan_type == NMAP_SCAN_FIN
		|| probe->scan_type == NMAP_SCAN_XMAS)
	{
		if (flags & NMAP_TCP_RST)
			return (SCAN_RESULT_CLOSED);
	}
	return (SCAN_RESULT_UNKNOWN);
}

/**
 * @brief Classify one matched ICMPv4 error.
 *
 * @note Unknown type/code pairs return UNKNOWN: they do not finalize the probe,
 *       so the runtime continues waiting/retransmitting according to policy.
 */
static t_scan_result	classify_icmp4(const t_nmap_config *config,
		const t_probe *probe, const t_nmap_reply *reply)
{
	if (reply->icmp_type == 11)
		return (SCAN_RESULT_FILTERED);
	if (reply->icmp_type != 3
		|| !icmp4_unreachable_code_is_known(reply->icmp_code))
		return (SCAN_RESULT_UNKNOWN);
	if (probe->scan_type == NMAP_SCAN_UDP && reply->icmp_code == 3)
	{
		if (nmap_ip_equal(&reply->src_addr, &config->target.addr))
			return (SCAN_RESULT_CLOSED);
		return (SCAN_RESULT_FILTERED);
	}
	return (SCAN_RESULT_FILTERED);
}

/**
 * @brief Classify one matched ICMPv6 error.
 *
 * Destination Unreachable (type 1) codes 0..6 are filtering/unreachable
 * evidence, except UDP port-unreachable 1/4 from the target itself -> CLOSED.
 * Parameter Problem 4/0 is treated as OPEN indication; 4/1 as FILTERED.
 */
static t_scan_result	classify_icmp6(const t_nmap_config *config,
		const t_probe *probe, const t_nmap_reply *reply)
{
	if (reply->icmp_type == 1 && reply->icmp_code <= 6)
	{
		if (probe->scan_type == NMAP_SCAN_UDP && reply->icmp_code == 4
			&& nmap_ip_equal(&reply->src_addr, &config->target.addr))
			return (SCAN_RESULT_CLOSED);
		return (SCAN_RESULT_FILTERED);
	}
	if (reply->icmp_type == 4 && reply->icmp_code == 0)
		return (SCAN_RESULT_OPEN);
	if (reply->icmp_type == 4 && reply->icmp_code == 1)
		return (SCAN_RESULT_FILTERED);
	return (SCAN_RESULT_UNKNOWN);
}

/**
 * @brief Apply the per-scan response decision tree to one already-matched reply.
 */
t_scan_result	nmap_classify_reply(const t_nmap_config *config,
		const t_probe *probe, const t_nmap_reply *reply)
{
	if (!config || !probe || !reply)
		return (SCAN_RESULT_UNKNOWN);
	if (reply->type == NMAP_REPLY_TCP && probe->scan_type != NMAP_SCAN_UDP)
		return (classify_tcp_packet(probe, reply));
	if (reply->type == NMAP_REPLY_UDP && probe->scan_type == NMAP_SCAN_UDP)
		return (SCAN_RESULT_OPEN);
	if (reply->type == NMAP_REPLY_ICMP4)
		return (classify_icmp4(config, probe, reply));
	if (reply->type == NMAP_REPLY_ICMP6)
		return (classify_icmp6(config, probe, reply));
	return (SCAN_RESULT_UNKNOWN);
}

/**
 * @brief Classify NO MATCHING RESPONSE AFTER RETRANSMISSION POLICY.
 */
t_scan_result	nmap_classify_no_response(uint32_t scan_type)
{
	if (scan_type == NMAP_SCAN_SYN || scan_type == NMAP_SCAN_ACK)
		return (SCAN_RESULT_FILTERED);
	if (scan_type == NMAP_SCAN_NULL || scan_type == NMAP_SCAN_FIN
		|| scan_type == NMAP_SCAN_XMAS || scan_type == NMAP_SCAN_UDP)
		return (SCAN_RESULT_OPEN_FILTERED);
	return (SCAN_RESULT_UNKNOWN);
}
