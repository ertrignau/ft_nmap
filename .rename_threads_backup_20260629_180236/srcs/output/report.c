#include "config.h"

#include <stdio.h>

/**
 * @brief Return the display name for a scan type.
 *
 * @param scan_type Concrete scan type.
 *
 * @return Static scan type name.
 */
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

/**
 * @brief Return the display name for a scan result.
 *
 * @param result Final scan result.
 *
 * @return Static result name.
 */
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

/**
 * @brief Return the display name for a non-final probe state.
 *
 * @param state Runtime probe state.
 *
 * @return Static state name.
 */
static const char	*probe_state_name(t_probe_state state)
{
	if (state == PROBE_PENDING)
		return ("pending");
	if (state == PROBE_IN_FLIGHT)
		return ("in-flight");
	if (state == PROBE_DONE)
		return ("done");
	return ("unknown");
}

/**
 * @brief Check whether a scan type is enabled in the scan mask.
 *
 * @param config Global nmap configuration.
 * @param scan_type Concrete scan type.
 *
 * @return 1 if enabled, 0 otherwise.
 */
static int	scan_type_enabled(t_nmap_config *config, uint32_t scan_type)
{
	return ((config->scan.scan_mask & scan_type) != 0);
}

/**
 * @brief Return the display string for a probe.
 *
 * @param probe Probe to display.
 *
 * @return Probe result if done, otherwise runtime state.
 */
static const char	*probe_display_result(t_probe *probe)
{
	if (!probe)
		return ("unknown");
	if (probe->state != PROBE_DONE)
		return (probe_state_name(probe->state));
	return (scan_result_name(probe->result));
}

/**
 * @brief Find a probe by port and scan type.
 *
 * @param config Global nmap configuration.
 * @param port Destination port.
 * @param scan_type Concrete scan type.
 *
 * @return Matching probe, or NULL if not found.
 */
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

/**
 * @brief Check whether a final result is boring for a scan type.
 *
 * @param probe Probe to check.
 *
 * @return 1 if the result is uninteresting, 0 otherwise.
 *
 * @note This is only a display filter. It does not change probe results.
 */
static int	probe_result_is_uninteresting(t_probe *probe)
{
	if (!probe)
		return (0);
	if (probe->state != PROBE_DONE)
		return (0);
	if (probe->scan_type == NMAP_SCAN_ACK
		&& probe->result == SCAN_RESULT_UNFILTERED)
		return (1);
	if (probe->scan_type == NMAP_SCAN_SYN
		&& probe->result == SCAN_RESULT_CLOSED)
		return (1);
	if (probe->scan_type == NMAP_SCAN_NULL
		&& probe->result == SCAN_RESULT_CLOSED)
		return (1);
	if (probe->scan_type == NMAP_SCAN_FIN
		&& probe->result == SCAN_RESULT_CLOSED)
		return (1);
	if (probe->scan_type == NMAP_SCAN_XMAS
		&& probe->result == SCAN_RESULT_CLOSED)
		return (1);
	if (probe->scan_type == NMAP_SCAN_UDP
		&& probe->result == SCAN_RESULT_CLOSED)
		return (1);
	return (0);
}

/**
 * @brief Check whether one scan column makes a port line interesting.
 *
 * @param config Global nmap configuration.
 * @param port Destination port.
 * @param scan_type Concrete scan type.
 *
 * @return 1 if this scan result should keep the line visible, 0 otherwise.
 */
static int	scan_column_is_interesting(t_nmap_config *config,
		uint16_t port, uint32_t scan_type)
{
	t_probe	*probe;

	if (!scan_type_enabled(config, scan_type))
		return (0);
	probe = find_probe(config, port, scan_type);
	if (!probe)
		return (1);
	return (!probe_result_is_uninteresting(probe));
}

/**
 * @brief Check whether a port line should be printed.
 *
 * @param config Global nmap configuration.
 * @param port Destination port.
 *
 * @return 1 if the line should be printed, 0 if it can be hidden.
 */
static int	port_line_is_interesting(t_nmap_config *config, uint16_t port)
{
	if (scan_column_is_interesting(config, port, NMAP_SCAN_SYN))
		return (1);
	if (scan_column_is_interesting(config, port, NMAP_SCAN_NULL))
		return (1);
	if (scan_column_is_interesting(config, port, NMAP_SCAN_FIN))
		return (1);
	if (scan_column_is_interesting(config, port, NMAP_SCAN_XMAS))
		return (1);
	if (scan_column_is_interesting(config, port, NMAP_SCAN_ACK))
		return (1);
	if (scan_column_is_interesting(config, port, NMAP_SCAN_UDP))
		return (1);
	return (0);
}

/**
 * @brief Print one enabled scan column in the header.
 *
 * @param config Global nmap configuration.
 * @param scan_type Concrete scan type.
 */
static void	print_header_column(t_nmap_config *config, uint32_t scan_type)
{
	if (scan_type_enabled(config, scan_type))
		printf("%-16s", scan_type_name(scan_type));
}

/**
 * @brief Print the report header.
 *
 * @param config Global nmap configuration.
 */
static void	print_report_header(t_nmap_config *config)
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

/**
 * @brief Print one scan result column for a port.
 *
 * @param config Global nmap configuration.
 * @param port Destination port.
 * @param scan_type Concrete scan type.
 */
static void	print_result_column(t_nmap_config *config,
		uint16_t port, uint32_t scan_type)
{
	t_probe	*probe;

	if (!scan_type_enabled(config, scan_type))
		return ;
	probe = find_probe(config, port, scan_type);
	printf("%-16s", probe_display_result(probe));
}

/**
 * @brief Print one destination port line.
 *
 * @param config Global nmap configuration.
 * @param port Destination port.
 */
static void	print_port_line(t_nmap_config *config, uint16_t port)
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
 * @brief Print the final scan report.
 *
 * @param config Global nmap configuration.
 *
 * @note The report does not classify or modify probes. It only displays the
 *       final state already produced by runtime/recv.c and runtime/expire.c.
 */
void	nmap_print_report(t_nmap_config *config)
{
	size_t	i;

	if (!config)
		return ;
	printf("Scan report for %s (%s)\n", config->cli.target,
		config->target.ip);
	printf("Probes: %zu total, %zu done, %zu in flight\n\n",
		config->runtime.probe_count,
		config->runtime.done_count,
		config->runtime.in_flight_count);
	print_report_header(config);
	i = 0;
	while (i < config->scan.port_count)
	{
		if (!config->cli.hide_uninteresting
			|| port_line_is_interesting(config, config->scan.ports[i]))
			print_port_line(config, config->scan.ports[i]);
		i++;
	}
}
