#include "config.h"

#include <stdlib.h>
#include <string.h>

/**
 * @brief Count how many concrete scan types are enabled.
 *
 * @param scan_mask Bitmask containing the requested scan types.
 *
 * @return Number of enabled scan types.
 */
static size_t	count_scan_types(uint32_t scan_mask)
{
	size_t	count;

	count = 0;
	if (scan_mask & NMAP_SCAN_SYN)
		count++;
	if (scan_mask & NMAP_SCAN_NULL)
		count++;
	if (scan_mask & NMAP_SCAN_FIN)
		count++;
	if (scan_mask & NMAP_SCAN_XMAS)
		count++;
	if (scan_mask & NMAP_SCAN_ACK)
		count++;
	/* UDP intentionally disabled for the current TCP-only engine step. */
	return (count);
}

/**
 * @brief Return the scan type matching an index in the scan mask.
 *
 * @param scan_mask Bitmask containing the requested scan types.
 * @param index Index of the enabled scan type to fetch.
 *
 * @return Concrete scan type, or 0 if the index is invalid.
 *
 * @note The order is stable and matches the expected output order.
 */
static uint32_t	get_scan_type_at(uint32_t scan_mask, size_t index)
{
	size_t	current;

	current = 0;
	if ((scan_mask & NMAP_SCAN_SYN) && current++ == index)
		return (NMAP_SCAN_SYN);
	if ((scan_mask & NMAP_SCAN_NULL) && current++ == index)
		return (NMAP_SCAN_NULL);
	if ((scan_mask & NMAP_SCAN_FIN) && current++ == index)
		return (NMAP_SCAN_FIN);
	if ((scan_mask & NMAP_SCAN_XMAS) && current++ == index)
		return (NMAP_SCAN_XMAS);
	if ((scan_mask & NMAP_SCAN_ACK) && current++ == index)
		return (NMAP_SCAN_ACK);
	/* UDP intentionally disabled for the current TCP-only engine step. */
	return (0);
}

/**
 * @brief Fill one runtime probe from the normalized scan plan.
 *
 * @param config Global nmap configuration.
 * @param probe Probe to initialize.
 * @param port Destination port.
 * @param scan_type Concrete scan type for this probe.
 * @param index Probe index in the runtime table.
 *
 * @return 1 on success, 0 if the generated source port is invalid.
 */
static int	init_probe(t_nmap_config *config, t_probe *probe,
		uint16_t port, uint32_t scan_type, size_t index)
{
	uint32_t	src_port;

	src_port = (uint32_t)config->scan.src_port_base + (uint32_t)index;
	if (src_port > 65535)
		return (0);
	memset(probe, 0, sizeof(*probe));
	probe->target_ip = config->target.addr.sin_addr.s_addr;
	probe->dst_port = port;
	probe->src_port = (uint16_t)src_port;
	probe->seq = 0x10000000u + (uint32_t)index;
	probe->scan_type = scan_type;
	probe->sent_at_ms = 0;
	probe->state = PROBE_PENDING;
	probe->result = SCAN_RESULT_UNKNOWN;
	return (1);
}

/**
 * @brief Fill the runtime probe table.
 *
 * @param config Global nmap configuration.
 * @param scan_type_count Number of enabled scan types.
 *
 * @return 1 on success, 0 if a probe cannot be initialized.
 */
static int	fill_probe_table(t_nmap_config *config, size_t scan_type_count)
{
	size_t		port_index;
	size_t		scan_index;
	size_t		probe_index;
	uint32_t	scan_type;

	probe_index = 0;
	port_index = 0;
	while (port_index < config->scan.port_count)
	{
		scan_index = 0;
		while (scan_index < scan_type_count)
		{
			scan_type = get_scan_type_at(config->scan.scan_mask, scan_index);
			if (!scan_type)
				return (0);
			if (!init_probe(config, &config->runtime.probes[probe_index],
					config->scan.ports[port_index], scan_type, probe_index))
				return (0);
			probe_index++;
			scan_index++;
		}
		port_index++;
	}
	return (1);
}

/**
 * @brief Initialize the runtime probe table from the scan plan.
 *
 * @param config Global nmap configuration.
 * @param exit_status Output exit status set on allocation or config error.
 *
 * @return 1 on success, 0 on failure.
 *
 * @note Runtime owns the probe table. It is freed by nmap_cleanup_config().
 */
int	nmap_prepare_runtime(t_nmap_config *config, int *exit_status)
{
	size_t	scan_type_count;
	size_t	probe_count;

	if (!config)
	{
		if (exit_status)
			*exit_status = 1;
		return (0);
	}
	scan_type_count = count_scan_types(config->scan.scan_mask);
	if (config->scan.port_count == 0 || scan_type_count == 0)
	{
		if (exit_status)
			*exit_status = 1;
		return (0);
	}
	probe_count = config->scan.port_count * scan_type_count;
	config->runtime.probes = malloc(sizeof(t_probe) * probe_count);
	if (!config->runtime.probes)
	{
		if (exit_status)
			*exit_status = 1;
		return (0);
	}
	config->runtime.probe_count = probe_count;
	config->runtime.next_to_send = 0;
	config->runtime.done_count = 0;
	config->runtime.in_flight_count = 0;
	if (!fill_probe_table(config, scan_type_count))
	{
		free(config->runtime.probes);
		memset(&config->runtime, 0, sizeof(config->runtime));
		if (exit_status)
			*exit_status = 1;
		return (0);
	}
	return (1);
}

/**
 * @brief Check whether all runtime probes have reached a final state.
 *
 * @param config Global nmap configuration.
 *
 * @return 1 if the runtime is finished, 0 otherwise.
 */
int	nmap_runtime_is_finished(t_nmap_config *config)
{
	if (!config)
		return (1);
	return (config->runtime.done_count >= config->runtime.probe_count);
}