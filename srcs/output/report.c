
#include "config.h"
#include "packet/wire.h"

#include <stdio.h>

/** Return the display name for one concrete scan type. */
static const char	*scan_type_name(uint32_t scan_type)
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

/** Return the display name for one final scan result. */
static const char	*scan_result_name(t_scan_result result)
{
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

/** Return the display name for one non-final runtime state. */
static const char	*probe_state_name(t_probe_state state)
{
	if (state == PROBE_PENDING)
		return ("pending");
	if (state == PROBE_QUEUED)
		return ("queued");
	if (state == PROBE_OUTSTANDING)
		return ("outstanding");
	if (state == PROBE_DONE)
		return ("done");
	return ("unknown");
}

/** Convert known ICMPv4 type/code pairs to concise report text. */
static const char	*icmp4_reason(uint8_t type, uint8_t code)
{
	if (type == 3 && code == 0)
		return ("net-unreachable");
	if (type == 3 && code == 1)
		return ("host-unreachable");
	if (type == 3 && code == 2)
		return ("protocol-unreachable");
	if (type == 3 && code == 3)
		return ("port-unreachable");
	if (type == 3 && code == 9)
		return ("net-prohibited");
	if (type == 3 && code == 10)
		return ("host-prohibited");
	if (type == 3 && code == 13)
		return ("admin-prohibited");
	if (type == 11 && code == 0)
		return ("ttl-exceeded");
	if (type == 11 && code == 1)
		return ("fragment-timeout");
	return (NULL);
}

/** Convert known ICMPv6 type/code pairs to concise report text. */
static const char	*icmp6_reason(uint8_t type, uint8_t code)
{
	if (type == 1 && code == 0)
		return ("no-route");
	if (type == 1 && code == 1)
		return ("admin-prohibited");
	if (type == 1 && code == 2)
		return ("beyond-scope");
	if (type == 1 && code == 3)
		return ("address-unreachable");
	if (type == 1 && code == 4)
		return ("port-unreachable");
	if (type == 1 && code == 5)
		return ("source-policy-failed");
	if (type == 1 && code == 6)
		return ("reject-route");
	if (type == 3 && code == 0)
		return ("hop-limit-exceeded");
	if (type == 3 && code == 1)
		return ("fragment-timeout");
	return (NULL);
}

/** Format the structured runtime reason without inventing protocol evidence. */
static void	format_scan_reason(const t_scan_reason *reason,
		char *buf, size_t size)
{
	const char	*name;

	if (!reason || size == 0)
		return ;
	if (reason->kind == SCAN_REASON_TCP)
	{
		if ((reason->tcp_flags & NMAP_TCP_SYN)
			&& (reason->tcp_flags & NMAP_TCP_ACK))
			snprintf(buf, size, "syn-ack");
		else if (reason->tcp_flags & NMAP_TCP_RST)
			snprintf(buf, size, "reset");
		else if (reason->tcp_flags & NMAP_TCP_SYN)
			snprintf(buf, size, "syn");
		else
			snprintf(buf, size, "tcp-flags-0x%02x", reason->tcp_flags);
		return ;
	}
	if (reason->kind == SCAN_REASON_UDP_REPLY)
		snprintf(buf, size, "udp-response");
	else if (reason->kind == SCAN_REASON_NO_RESPONSE)
		snprintf(buf, size, "no-response");
	else if (reason->kind == SCAN_REASON_SEND_ERROR)
		snprintf(buf, size, "send-error");
	else if (reason->kind == SCAN_REASON_ICMP)
	{
		name = NULL;
		if (reason->family == AF_INET)
			name = icmp4_reason(reason->icmp_type, reason->icmp_code);
		else if (reason->family == AF_INET6)
			name = icmp6_reason(reason->icmp_type, reason->icmp_code);
		if (name)
			snprintf(buf, size, "%s", name);
		else if (reason->family == AF_INET6)
			snprintf(buf, size, "icmp6-%u/%u",
				reason->icmp_type, reason->icmp_code);
		else
			snprintf(buf, size, "icmp-%u/%u",
				reason->icmp_type, reason->icmp_code);
	}
	else
		snprintf(buf, size, "none");
}

/** Check whether one scan column is enabled. */
static int	scan_enabled(const t_nmap_config *config, uint32_t scan_type)
{
	return ((config->scan.scan_mask & scan_type) != 0);
}

/** Find one logical probe by destination port and scan type. */
static t_probe	*find_probe(t_nmap_config *config,
		uint16_t port, uint32_t scan_type)
{
	size_t	i;

	i = 0;
	while (i < config->runtime.probe_count)
	{
		if (config->runtime.probes[i].dst_port == port
			&& config->runtime.probes[i].scan_type == scan_type)
			return (&config->runtime.probes[i]);
		i++;
	}
	return (NULL);
}

/** Display a final result when DONE, otherwise the live runtime state. */
static const char	*probe_display(const t_probe *probe)
{
	if (!probe)
		return ("unknown");
	if (probe->state != PROBE_DONE)
		return (probe_state_name(probe->state));
	return (scan_result_name(probe->result));
}

/** Return whether a DONE result counts as open-like for --open filtering. */
static int	probe_is_open_like(const t_probe *probe)
{
	if (!probe || probe->state != PROBE_DONE)
		return (0);
	return (probe->result == SCAN_RESULT_OPEN
		|| probe->result == SCAN_RESULT_OPEN_FILTERED);
}

/** Check whether any enabled scan keeps one port visible in --open mode. */
static int	port_is_open_like(t_nmap_config *config, uint16_t port)
{
	static const uint32_t	types[] = {
		NMAP_SCAN_SYN, NMAP_SCAN_NULL, NMAP_SCAN_FIN,
		NMAP_SCAN_XMAS, NMAP_SCAN_ACK, NMAP_SCAN_UDP
	};
	size_t				i;

	i = 0;
	while (i < sizeof(types) / sizeof(types[0]))
	{
		if (scan_enabled(config, types[i])
			&& probe_is_open_like(find_probe(config, port, types[i])))
			return (1);
		i++;
	}
	return (0);
}

/** Print one enabled result-table header column. */
static void	print_header_column(const t_nmap_config *config, uint32_t type)
{
	if (scan_enabled(config, type))
		printf("%-28s", scan_type_name(type));
}

/** Print one enabled result-table cell, optionally with --reason. */
static void	print_result_column(t_nmap_config *config,
		uint16_t port, uint32_t type)
{
	t_probe	*probe;
	char	reason[48];
	char	cell[96];

	if (!scan_enabled(config, type))
		return ;
	probe = find_probe(config, port, type);
	if (!config->scan.show_reason || !probe || probe->state != PROBE_DONE)
	{
		printf("%-28s", probe_display(probe));
		return ;
	}
	format_scan_reason(&probe->reason, reason, sizeof(reason));
	snprintf(cell, sizeof(cell), "%s(%s)", probe_display(probe), reason);
	printf("%-28s", cell);
}

/** Print the report table header in stable scan order. */
static void	print_header(const t_nmap_config *config)
{
	printf("%-8s", "PORT");
	print_header_column(config, NMAP_SCAN_SYN);
	print_header_column(config, NMAP_SCAN_NULL);
	print_header_column(config, NMAP_SCAN_FIN);
	print_header_column(config, NMAP_SCAN_XMAS);
	print_header_column(config, NMAP_SCAN_ACK);
	print_header_column(config, NMAP_SCAN_UDP);
	printf("\n");
}

/** Print all enabled scan results for one destination port. */
static void	print_port(t_nmap_config *config, uint16_t port)
{
	printf("%-8u", port);
	print_result_column(config, port, NMAP_SCAN_SYN);
	print_result_column(config, port, NMAP_SCAN_NULL);
	print_result_column(config, port, NMAP_SCAN_FIN);
	print_result_column(config, port, NMAP_SCAN_XMAS);
	print_result_column(config, port, NMAP_SCAN_ACK);
	print_result_column(config, port, NMAP_SCAN_UDP);
	printf("\n");
}

/** @brief Print the current-target scan report without modifying runtime state. */
void	nmap_print_report(t_nmap_config *config)
{
	size_t	i;

	if (!config)
		return ;
	printf("Scan report for %s (%s)\n",
		config->target.name, config->target.ip);
	printf("Probes: %zu total, %zu done, %zu queued, %zu outstanding\n\n",
		config->runtime.probe_count,
		config->runtime.done_count,
		config->runtime.queued_count,
		config->runtime.outstanding_count);
	print_header(config);
	i = 0;
	while (i < config->scan.port_count)
	{
		if (!config->scan.open_only
			|| port_is_open_like(config, config->scan.ports[i]))
			print_port(config, config->scan.ports[i]);
		i++;
	}
}
