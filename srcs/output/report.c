#include "config.h"

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
		NMAP_SCAN_SYN,
		NMAP_SCAN_NULL,
		NMAP_SCAN_FIN,
		NMAP_SCAN_XMAS,
		NMAP_SCAN_ACK,
		NMAP_SCAN_UDP
	};
	size_t					i;

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
		printf("%-16s", scan_type_name(type));
}

/** Print one enabled result-table cell. */
static void	print_result_column(t_nmap_config *config,
		uint16_t port, uint32_t type)
{
	if (scan_enabled(config, type))
		printf("%-16s", probe_display(find_probe(config, port, type)));
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

/**
 * @brief Print the current-target scan report without modifying runtime state.
 */
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
