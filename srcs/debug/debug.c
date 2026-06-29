#include "debug/debug.h"

#ifdef DEBUG

# include <ctype.h>
# include <stdio.h>
# include <arpa/inet.h>

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

static const char	*debug_probe_state_name(t_probe_state state)
{
	if (state == PROBE_PENDING)
		return ("PENDING");
	if (state == PROBE_QUEUED)
		return ("QUEUED");
	if (state == PROBE_IN_FLIGHT)
		return ("IN_FLIGHT");
	if (state == PROBE_DONE)
		return ("DONE");
	return ("UNKNOWN");
}

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

void	nmap_debug_dev_config(const t_nmap_config *config)
{
	if (!config)
		return ;
	fprintf(stderr, "[debug][config] target=%s target_ip=%s\n",
		config->cli.target, config->target.ip);
	fprintf(stderr, "[debug][config] iface=%s src_ip=%s\n",
		config->route.iface, config->route.src_ip);
	fprintf(stderr, "[debug][config] ports=%s count=%zu scan_mask=0x%x\n",
		config->cli.ports_arg, config->scan.port_count,
		config->scan.scan_mask);
	fprintf(stderr, "[debug][config] timeout_ms=%d max_in_flight=%d src_port_base=%u\n",
		config->scan.timeout_ms, config->scan.max_in_flight,
		config->scan.src_port_base);
}

void	nmap_debug_socket(const t_nmap_config *config)
{
	if (!config)
		return ;
	fprintf(stderr, "[debug][socket] send_fd=%d\n",
		config->socket.send_fd);
}

void	nmap_debug_pcap(const t_nmap_config *config)
{
	if (!config)
		return ;
	fprintf(stderr, "[debug][pcap] handle=%p fd=%d datalink=%d\n",
		(void *)config->capture.handle, config->capture.fd,
		config->capture.datalink);
}

void	nmap_debug_runtime(const t_nmap_config *config)
{
	if (!config)
		return ;
	fprintf(stderr, "[debug][runtime] probes=%p count=%zu next=%zu done=%zu queued=%zu in_flight=%zu\n",
		(void *)config->runtime.probes,
		config->runtime.probe_count,
		config->runtime.next_to_send,
		config->runtime.done_count,
		config->runtime.queued_count,
		config->runtime.in_flight_count);
}

void	nmap_debug_probe_send(const t_probe *probe)
{
	struct in_addr	addr;
	char			ip[INET_ADDRSTRLEN];

	if (!probe)
		return ;
	addr.s_addr = probe->target_ip;
	if (!inet_ntop(AF_INET, &addr, ip, sizeof(ip)))
		snprintf(ip, sizeof(ip), "unknown");
	fprintf(stderr,
		"[debug][send][probe] target=%s dst_port=%u src_port=%u scan=%s seq=%u state=%s\n",
		ip,
		probe->dst_port,
		probe->src_port,
		debug_scan_type_name(probe->scan_type),
		probe->seq,
		debug_probe_state_name(probe->state));
}

void	nmap_debug_probe_timeout(const t_probe *probe)
{
	struct in_addr	addr;
	char			ip[INET_ADDRSTRLEN];

	if (!probe)
		return ;
	addr.s_addr = probe->target_ip;
	if (!inet_ntop(AF_INET, &addr, ip, sizeof(ip)))
		snprintf(ip, sizeof(ip), "unknown");
	fprintf(stderr,
		"[debug][timeout][probe] target=%s dst_port=%u src_port=%u scan=%s sent_at_ms=%llu\n",
		ip,
		probe->dst_port,
		probe->src_port,
		debug_scan_type_name(probe->scan_type),
		(unsigned long long)probe->sent_at_ms);
}

void	nmap_debug_probe_result(const t_probe *probe, const char *reason)
{
	struct in_addr	addr;
	char			ip[INET_ADDRSTRLEN];

	if (!probe)
		return ;
	addr.s_addr = probe->target_ip;
	if (!inet_ntop(AF_INET, &addr, ip, sizeof(ip)))
		snprintf(ip, sizeof(ip), "unknown");
	fprintf(stderr,
		"[debug][result][probe] target=%s dst_port=%u src_port=%u scan=%s result=%s reason=%s\n",
		ip,
		probe->dst_port,
		probe->src_port,
		debug_scan_type_name(probe->scan_type),
		debug_scan_result_name(probe->result),
		reason);
}

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