#include "config.h"
#include "debug/debug.h"

#include <stdio.h>
#include <sys/time.h>

int	nmap_send_tcp_probe(t_nmap_config *config, t_probe *probe);

/**
 * @brief Return current time in milliseconds.
 *
 * @return Current timestamp in milliseconds.
 */
static uint64_t	get_time_ms(void)
{
	struct timeval	tv;

	gettimeofday(&tv, NULL);
	return ((uint64_t)tv.tv_sec * 1000 + (uint64_t)tv.tv_usec / 1000);
}

/**
 * @brief Check whether a scan type is TCP-based.
 *
 * @param scan_type Scan type stored in the probe.
 *
 * @return 1 for TCP scans, 0 otherwise.
 */
static int	is_tcp_scan(uint32_t scan_type)
{
	return (scan_type == NMAP_SCAN_SYN
		|| scan_type == NMAP_SCAN_NULL
		|| scan_type == NMAP_SCAN_FIN
		|| scan_type == NMAP_SCAN_XMAS
		|| scan_type == NMAP_SCAN_ACK);
}

/**
 * @brief Send one runtime probe through the packet layer.
 *
 * @param config Global nmap configuration.
 * @param probe Probe selected by the scheduler.
 *
 * @return 1 on success, 0 on packet send failure.
 *
 * @note This function does not build packets. It only chooses the packet
 *       sender matching the probe scan type.
 */
static int	send_probe(t_nmap_config *config, t_probe *probe)
{
	if (is_tcp_scan(probe->scan_type))
		return (nmap_send_tcp_probe(config, probe));
	fprintf(stderr, "ft_nmap: invalid TCP scan type: 0x%x\n", probe->scan_type);
	return (0);
}

/**
 * @brief Mark a probe as in flight after a successful send.
 *
 * @param config Global nmap configuration.
 * @param probe Probe that has just been sent.
 */
static void	mark_probe_in_flight(t_nmap_config *config, t_probe *probe)
{
	probe->sent_at_ms = get_time_ms();
	probe->state = PROBE_IN_FLIGHT;
	config->runtime.in_flight_count++;
}

/**
 * @brief Send pending probes while the scheduler allows it.
 *
 * @param config Global nmap configuration.
 * @param exit_status Output exit status set on fatal send error.
 *
 * @return 1 on success, 0 on fatal send error.
 *
 * @note At most config->scan.max_in_flight probes can be in flight at once.
 */
int	nmap_runtime_send_ready(t_nmap_config *config, int *exit_status)
{
	t_probe	*probe;

	if (!config || config->scan.max_in_flight <= 0)
	{
		if (exit_status)
			*exit_status = 1;
		return (0);
	}
	while (config->runtime.next_to_send < config->runtime.probe_count
		&& config->runtime.in_flight_count
		< (size_t)config->scan.max_in_flight)
	{
		probe = &config->runtime.probes[config->runtime.next_to_send];
		config->runtime.next_to_send++;
		if (probe->state != PROBE_PENDING)
			continue ;
		DEBUG_PROBE_SEND(probe);
		if (!send_probe(config, probe))
		{
			if (exit_status)
				*exit_status = 1;
			return (0);
		}
		mark_probe_in_flight(config, probe);
	}
	return (1);
}