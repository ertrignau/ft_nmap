#include "config.h"
#include "debug/debug.h"
#include "runtime/worker.h"

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
 * @brief Check whether a parsed reply matches a candidate probe.
 *
 * @param probe Runtime probe found by source-port index.
 * @param reply Parsed reply.
 *
 * @return 1 if the reply matches the probe, 0 otherwise.
 */
static int	reply_matches_probe(t_nmap_config *config,
		t_probe *probe, t_nmap_reply *reply)
{
	if (!probe || probe->state != PROBE_IN_FLIGHT)
		return (0);
	if (reply->type == NMAP_REPLY_TCP || reply->type == NMAP_REPLY_UDP)
		return (reply_matches_direct_probe(config, probe, reply));
	if (reply->type == NMAP_REPLY_ICMP)
		return (reply_matches_icmp_probe(config, probe, reply));
	return (0);
}

/**
 * @brief Return the source-port index key carried by a reply.
 *
 * @param reply Parsed reply.
 * @param key Output source-port key.
 *
 * @return 1 if a key is available, 0 otherwise.
 */
static int	reply_index_key(t_nmap_reply *reply, uint16_t *key)
{
	if (reply->type == NMAP_REPLY_TCP || reply->type == NMAP_REPLY_UDP)
	{
		*key = reply->dst_port;
		return (1);
	}
	if (reply->type == NMAP_REPLY_ICMP)
	{
		*key = reply->original_src_port;
		return (1);
	}
	return (0);
}

/**
 * @brief Find the in-flight probe matching a parsed reply.
 *
 * @param config Global nmap configuration.
 * @param reply Parsed reply.
 *
 * @return Matching probe pointer, or NULL if no probe matches.
 *
 * @note The lookup is O(1) through source port, then all IP/port/protocol fields
 *       are still validated before accepting the match.
 */
static t_probe	*find_matching_probe(t_nmap_config *config, t_nmap_reply *reply)
{
	t_probe		*probe;
	uint16_t	key;

	if (!reply_index_key(reply, &key))
		return (NULL);
	probe = config->runtime.probe_by_src_port[key];
	if (!reply_matches_probe(config, probe, reply))
		return (NULL);
	return (probe);
}

/**
 * @brief Check whether a probe is UDP.
 *
 * @param probe Probe to inspect.
 *
 * @return 1 for UDP, 0 otherwise.
 */
static int	probe_is_udp(t_probe *probe)
{
	return (probe && probe->scan_type == NMAP_SCAN_UDP);
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
	pthread_mutex_lock(&config->sender_pool.runtime_lock);
	if (probe->state == PROBE_DONE)
	{
		pthread_mutex_unlock(&config->sender_pool.runtime_lock);
		return ;
	}
	probe->result = result;
	probe->state = PROBE_DONE;
	if (config->runtime.in_flight_count > 0)
		config->runtime.in_flight_count--;
	if (probe_is_udp(probe) && config->runtime.udp_in_flight_count > 0)
		config->runtime.udp_in_flight_count--;
	nmap_sender_note_probe_done_locked(config, probe);
	config->runtime.done_count++;
	pthread_mutex_unlock(&config->sender_pool.runtime_lock);
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
	uint64_t		prof_start;
	int				parsed;

	DEBUG_RECV_PACKET(packet, len);
	prof_start = PROF_START();
	parsed = nmap_parse_pcap_packet(config, packet, len, &reply);
	PROF_ADD(NMAP_PROF_PACKET_PARSE_TOTAL, prof_start);
	if (!parsed)
	{
		PROF_COUNT(NMAP_PROF_PACKET_IGNORED);
		return (0);
	}
	PROF_COUNT(NMAP_PROF_PACKET_PARSED);
	prof_start = PROF_START();
	pthread_mutex_lock(&config->sender_pool.runtime_lock);
	probe = find_matching_probe(config, &reply);
	pthread_mutex_unlock(&config->sender_pool.runtime_lock);
	PROF_ADD(NMAP_PROF_MATCH_PROBE, prof_start);
	if (!probe)
	{
		PROF_COUNT(NMAP_PROF_PACKET_IGNORED);
		return (0);
	}
	prof_start = PROF_START();
	result = nmap_classify_reply(probe, &reply);
	PROF_ADD(NMAP_PROF_CLASSIFY, prof_start);
	if (result == SCAN_RESULT_UNKNOWN)
	{
		PROF_COUNT(NMAP_PROF_PACKET_IGNORED);
		return (0);
	}
	PROF_COUNT(NMAP_PROF_PACKET_MATCHED);
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
