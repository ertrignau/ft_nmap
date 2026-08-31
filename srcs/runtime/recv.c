
#include "config.h"
#include "debug/debug.h"
#include "packet/packet.h"
#include "runtime/runtime_internal.h"

#include <pcap/pcap.h>
#include <stdio.h>

/** Return structured report evidence represented by one matched reply. */
static t_scan_reason	reply_reason(const t_nmap_reply *reply)
{
	t_scan_reason	reason;

	reason = (t_scan_reason){0};
	if (!reply)
		return (reason);
	if (reply->type == NMAP_REPLY_UDP)
		reason.kind = SCAN_REASON_UDP_REPLY;
	else if (reply->type == NMAP_REPLY_TCP)
	{
		reason.kind = SCAN_REASON_TCP;
		reason.tcp_flags = reply->tcp_flags;
	}
	else if (reply->type == NMAP_REPLY_ICMP4
		|| reply->type == NMAP_REPLY_ICMP6)
	{
		reason.kind = SCAN_REASON_ICMP;
		if (reply->type == NMAP_REPLY_ICMP4)
			reason.family = AF_INET;
		else
			reason.family = AF_INET6;
		reason.icmp_type = reply->icmp_type;
		reason.icmp_code = reply->icmp_code;
	}
	return (reason);
}

/**
 * @brief Parse, match and classify one captured frame.
 *
 * @return 1 when the frame finalized a probe, 0 when it was safely ignored.
 */
static int	handle_captured_packet(t_nmap_config *config,
		const unsigned char *packet, size_t len)
{
	t_nmap_reply	reply;
	t_probe			*probe;
	t_scan_result	result;
	uint64_t		prof_start;

	DEBUG_RECV_PACKET(packet, len);
	prof_start = PROF_START();
	if (!nmap_parse_pcap_packet(config, packet, len, &reply))
	{
		PROF_ADD(NMAP_PROF_PACKET_PARSE_TOTAL, prof_start);
		PROF_COUNT(NMAP_PROF_PACKET_IGNORED);
		return (0);
	}
	PROF_ADD(NMAP_PROF_PACKET_PARSE_TOTAL, prof_start);
	PROF_COUNT(NMAP_PROF_PACKET_PARSED);
	prof_start = PROF_START();
	probe = nmap_find_matching_probe(config, &reply);
	PROF_ADD(NMAP_PROF_MATCH_PROBE, prof_start);
	if (!probe)
	{
		PROF_COUNT(NMAP_PROF_PACKET_IGNORED);
		return (0);
	}
	prof_start = PROF_START();
	result = nmap_classify_reply(config, probe, &reply);
	PROF_ADD(NMAP_PROF_CLASSIFY, prof_start);
	if (result == SCAN_RESULT_UNKNOWN)
	{
		PROF_COUNT(NMAP_PROF_PACKET_IGNORED);
		return (0);
	}
	PROF_COUNT(NMAP_PROF_PACKET_MATCHED);
	nmap_mark_probe_done(config, probe, result, reply_reason(&reply), "reply");
	return (1);
}

/** @brief Drain every pcap frame currently available without blocking. */
int	nmap_runtime_drain_replies(t_nmap_config *config, int *exit_status)
{
	struct pcap_pkthdr	*header;
	const unsigned char	*packet;
	int					ret;
	uint64_t			prof_start;

	if (!config || !config->capture.handle)
	{
		if (exit_status)
			*exit_status = 1;
		return (0);
	}
	while (1)
	{
		prof_start = PROF_START();
		ret = pcap_next_ex(config->capture.handle, &header, &packet);
		PROF_ADD(NMAP_PROF_PCAP_NEXT_EX, prof_start);
		if (ret == 1)
		{
			PROF_COUNT(NMAP_PROF_PACKET_SEEN);
			handle_captured_packet(config, packet, header->caplen);
		}
		else if (ret == 0 || ret == PCAP_ERROR_BREAK)
			return (1);
		else
		{
			fprintf(stderr, "ft_nmap: pcap_next_ex: %s\n",
				pcap_geterr(config->capture.handle));
			if (exit_status)
				*exit_status = 1;
			return (0);
		}
	}
}
