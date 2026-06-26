#include "config.h"
#include "debug/debug.h"

#include <stdio.h>
#include <netinet/in.h>
#include <pcap/pcap.h>

int				nmap_parse_pcap_packet(t_nmap_config *config,
					const unsigned char *packet, size_t len,
					t_nmap_reply *reply);
t_scan_result	nmap_classify_reply(t_probe *probe, t_nmap_reply *reply);

/**
 * @brief Check whether a direct TCP or UDP reply matches a probe.
 *
 * @param probe Runtime probe to test.
 * @param reply Parsed packet reply.
 *
 * @return 1 if the reply matches the probe, 0 otherwise.
 */
static int	reply_matches_direct_probe(t_nmap_config *config,
		t_probe *probe, t_nmap_reply *reply)
{
	if (reply->src_ip != probe->target_ip)
		return (0);
	if (reply->dst_ip != config->route.src_addr.sin_addr.s_addr)
		return (0);
	if (reply->src_port != probe->dst_port)
		return (0);
	if (reply->dst_port != probe->src_port)
		return (0);
	if (reply->type == NMAP_REPLY_TCP && probe->scan_type != NMAP_SCAN_UDP)
		return (1);
	if (reply->type == NMAP_REPLY_UDP && probe->scan_type == NMAP_SCAN_UDP)
		return (1);
	return (0);
}

/**
 * @brief Check whether an ICMP error reply matches a probe.
 *
 * @param probe Runtime probe to test.
 * @param reply Parsed ICMP reply.
 *
 * @return 1 if the embedded original packet matches the probe, 0 otherwise.
 */
static int	reply_matches_icmp_probe(t_nmap_config *config,
		t_probe *probe, t_nmap_reply *reply)
{
	if (reply->original_src_ip != config->route.src_addr.sin_addr.s_addr)
		return (0);
	if (reply->original_dst_ip != probe->target_ip)
		return (0);
	if (reply->original_dst_port != probe->dst_port)
		return (0);
	if (reply->original_src_port != probe->src_port)
		return (0);
	if (reply->original_protocol == IPPROTO_TCP
		&& probe->scan_type != NMAP_SCAN_UDP)
		return (1);
	if (reply->original_protocol == IPPROTO_UDP
		&& probe->scan_type == NMAP_SCAN_UDP)
		return (1);
	return (0);
}

/**
 * @brief Check whether a parsed reply matches a probe.
 *
 * @param probe Runtime probe to test.
 * @param reply Parsed reply.
 *
 * @return 1 if the reply matches the probe, 0 otherwise.
 */
static int	reply_matches_probe(t_nmap_config *config,
		t_probe *probe, t_nmap_reply *reply)
{
	if (probe->state != PROBE_IN_FLIGHT)
		return (0);
	if (reply->type == NMAP_REPLY_TCP || reply->type == NMAP_REPLY_UDP)
		return (reply_matches_direct_probe(config, probe, reply));
	if (reply->type == NMAP_REPLY_ICMP)
		return (reply_matches_icmp_probe(config, probe, reply));
	return (0);
}

/**
 * @brief Find the in-flight probe matching a parsed reply.
 *
 * @param config Global nmap configuration.
 * @param reply Parsed reply.
 *
 * @return Matching probe pointer, or NULL if no probe matches.
 */
static t_probe	*find_matching_probe(t_nmap_config *config, t_nmap_reply *reply)
{
	size_t	i;

	i = 0;
	while (i < config->runtime.probe_count)
	{
		if (reply_matches_probe(config, &config->runtime.probes[i], reply))
			return (&config->runtime.probes[i]);
		i++;
	}
	return (NULL);
}

/**
 * @brief Mark a matched probe as done.
 *
 * @param config Global nmap configuration.
 * @param probe Matched runtime probe.
 * @param result Classification result.
 */
static void	mark_probe_done(t_nmap_config *config, t_probe *probe,
		t_scan_result result)
{
	probe->result = result;
	probe->state = PROBE_DONE;
	if (config->runtime.in_flight_count > 0)
		config->runtime.in_flight_count--;
	config->runtime.done_count++;
	DEBUG_PROBE_RESULT(probe, "reply");
}

/**
 * @brief Handle one captured packet.
 *
 * @param config Global nmap configuration.
 * @param packet Captured packet buffer.
 * @param len Captured packet length.
 *
 * @return 1 on success, 0 when parsing/matching/classification should ignore it.
 */
static int	handle_captured_packet(t_nmap_config *config,
		const unsigned char *packet, size_t len)
{
	t_nmap_reply	reply;
	t_probe			*probe;
	t_scan_result	result;

	DEBUG_RECV_PACKET(packet, len);
	if (!nmap_parse_pcap_packet(config, packet, len, &reply))
		return (0);
	probe = find_matching_probe(config, &reply);
	if (!probe)
		return (0);
	result = nmap_classify_reply(probe, &reply);
	if (result == SCAN_RESULT_UNKNOWN)
		return (0);
	mark_probe_done(config, probe, result);
	return (1);
}

/**
 * @brief Drain all currently available pcap packets.
 *
 * @param config Global nmap configuration.
 * @param exit_status Output exit status set on fatal pcap error.
 *
 * @return 1 on success, 0 on fatal pcap error.
 *
 * @note The pcap handle is non-blocking. This function reads until pcap says
 *       there is no packet immediately available.
 */
int	nmap_runtime_drain_replies(t_nmap_config *config, int *exit_status)
{
	struct pcap_pkthdr	*header;
	const unsigned char	*packet;
	int					ret;

	if (!config || !config->capture.handle)
	{
		if (exit_status)
			*exit_status = 1;
		return (0);
	}
	while (1)
	{
		ret = pcap_next_ex(config->capture.handle, &header, &packet);
		if (ret == 1)
			handle_captured_packet(config, packet, header->caplen);
		else if (ret == 0)
			return (1);
		else if (ret == PCAP_ERROR_BREAK)
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