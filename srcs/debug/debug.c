#include "debug/debug.h"
#include "net/address.h"

#ifdef DEBUG

# include <ctype.h>
# include <stdio.h>

/** Return a readable scan-type name for debug output. */
static const char	*debug_scan_type_name(uint32_t scan_type)
{
	if (scan_type == NMAP_SCAN_SYN)
		return ("SYN");
	if (scan_type == NMAP_SCAN_NULL)
		return ("NULL");
	if (scan_type == NMAP_SCAN_FIN)
		return ("FIN");
	if (scan_type == NMAP_SCAN_XMAS)
		return ("XMAS");
	if (scan_type == NMAP_SCAN_ACK)
		return ("ACK");
	if (scan_type == NMAP_SCAN_UDP)
		return ("UDP");
	return ("UNKNOWN");
}

/** Return a readable probe-lifecycle state name. */
static const char	*debug_probe_state_name(t_probe_state state)
{
	if (state == PROBE_PENDING)
		return ("PENDING");
	if (state == PROBE_QUEUED)
		return ("QUEUED");
	if (state == PROBE_OUTSTANDING)
		return ("OUTSTANDING");
	if (state == PROBE_DONE)
		return ("DONE");
	return ("UNKNOWN");
}

/** Return a readable scan result name. */
static const char	*debug_scan_result_name(t_scan_result result)
{
	if (result == SCAN_RESULT_UNKNOWN)
		return ("unknown");
	if (result == SCAN_RESULT_OPEN)
		return ("open");
	if (result == SCAN_RESULT_CLOSED)
		return ("closed");
	if (result == SCAN_RESULT_FILTERED)
		return ("filtered");
	if (result == SCAN_RESULT_UNFILTERED)
		return ("unfiltered");
	if (result == SCAN_RESULT_OPEN_FILTERED)
		return ("open|filtered");
	return ("unknown");
}

/** Print resolved target, route and effective scan policy. */
void	nmap_debug_dev_config(const t_nmap_config *config)
{
	if (!config)
		return ;
	fprintf(stderr, "[debug][config] target=%s target_ip=%s family=%d\n",
		config->target.name, config->target.ip, config->target.addr.family);
	fprintf(stderr, "[debug][config] iface=%s ifindex=%u src_ip=%s\n",
		config->route.iface, config->route.ifindex, config->route.src_ip);
	fprintf(stderr,
		"[debug][config] ports=%zu scan_mask=0x%x retries=%d tcp_timeout=%d udp_timeout=%d\n",
		config->scan.port_count, config->scan.scan_mask, config->scan.retries,
		config->scan.tcp_timeout_ms, config->scan.udp_timeout_ms);
	fprintf(stderr,
		"[debug][config] threads=%d window=%d udp_window=%d udp_gap_ms=%d\n",
		config->scan.thread_count, config->scan.window_size,
		config->scan.udp_window_size, config->scan.udp_dispatch_gap_ms);
}

/** Print raw socket state. */
void	nmap_debug_socket(const t_nmap_config *config)
{
	if (!config)
		return ;
	fprintf(stderr, "[debug][socket] send_fd=%d family=%d\n",
		config->socket.send_fd, config->socket.family);
}

/** Print pcap state. */
void	nmap_debug_pcap(const t_nmap_config *config)
{
	if (!config)
		return ;
	fprintf(stderr, "[debug][pcap] handle=%p fd=%d datalink=%d\n",
		(void *)config->capture.handle, config->capture.fd,
		config->capture.datalink);
}

/** Print aggregate runtime counters. */
void	nmap_debug_runtime(const t_nmap_config *config)
{
	if (!config)
		return ;
	fprintf(stderr,
		"[debug][runtime] probes=%zu done=%zu queued=%zu outstanding=%zu src_base=%u\n",
		config->runtime.probe_count, config->runtime.done_count,
		config->runtime.queued_count, config->runtime.outstanding_count,
		config->runtime.source_port_base);
}

/** Print one send attempt. */
void	nmap_debug_probe_send(const t_probe *probe)
{
	if (!probe)
		return ;
	fprintf(stderr,
		"[debug][send][probe] dst_port=%u src_port=%u scan=%s seq=%u attempt=%u state=%s dispatch=%u\n",
		probe->dst_port, probe->src_port, debug_scan_type_name(probe->scan_type),
		probe->seq, probe->attempts_sent,
		debug_probe_state_name(probe->state), probe->dispatch_id);
}

/** Print one attempt timeout. */
void	nmap_debug_probe_timeout(const t_probe *probe)
{
	if (!probe)
		return ;
	fprintf(stderr,
		"[debug][timeout][probe] dst_port=%u src_port=%u scan=%s attempt=%u sent_at_ms=%llu\n",
		probe->dst_port, probe->src_port, debug_scan_type_name(probe->scan_type),
		probe->attempts_sent, (unsigned long long)probe->sent_at_ms);
}

/** Print one final logical probe result. */
void	nmap_debug_probe_result(const t_probe *probe, const char *reason)
{
	if (!probe)
		return ;
	fprintf(stderr,
		"[debug][result][probe] dst_port=%u src_port=%u scan=%s result=%s reason=%s\n",
		probe->dst_port, probe->src_port, debug_scan_type_name(probe->scan_type),
		debug_scan_result_name(probe->result), reason ? reason : "unknown");
}

/** Print an exact packet buffer in classic 16-byte hexdump form. */
void	nmap_debug_hexdump(const char *title, const void *data, size_t len)
{
	const unsigned char	*bytes;
	size_t				i;
	size_t				j;

	if (!data)
		return ;
	bytes = (const unsigned char *)data;
	fprintf(stderr, "%s len=%zu\n", title, len);
	i = 0;
	while (i < len)
	{
		fprintf(stderr, "  %04zx  ", i);
		j = 0;
		while (j < 16)
		{
			if (i + j < len)
				fprintf(stderr, "%02x ", bytes[i + j]);
			else
				fprintf(stderr, "   ");
			if (j == 7)
				fprintf(stderr, " ");
			j++;
		}
		fprintf(stderr, " |");
		j = 0;
		while (j < 16 && i + j < len)
		{
			if (isprint(bytes[i + j]))
				fprintf(stderr, "%c", bytes[i + j]);
			else
				fprintf(stderr, ".");
			j++;
		}
		fprintf(stderr, "|\n");
		i += 16;
	}
}

#endif
