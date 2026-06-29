#include "config.h"
#include "debug/debug.h"

#include <stdio.h>
#include <sys/time.h>

int	nmap_send_tcp_probe(t_nmap_config *config, t_probe *probe);
int	nmap_send_udp_probe(t_nmap_config *config, t_probe *probe);

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
	if (probe->scan_type == NMAP_SCAN_UDP)
		return (nmap_send_udp_probe(config, probe));
	fprintf(stderr, "ft_nmap: invalid scan type: 0x%x\n", probe->scan_type);
	return (0);
}

/**
 * @brief Check whether global UDP pacing allows a send now.
 *
 * @param config Global nmap configuration.
 * @param now_ms Current timestamp in milliseconds.
 *
 * @return 1 if a UDP probe can be sent now, 0 otherwise.
 *
 * @note The gap is global. It is not per thread, otherwise speedup would bypass
 *       the ICMP rate-limit protection.
 */
static int	udp_gap_allows_send(t_nmap_config *config, uint64_t now_ms)
{
	uint64_t	elapsed;

	if (config->scan.udp_send_gap_ms <= 0)
		return (1);
	if (config->runtime.last_udp_send_ms == 0)
		return (1);
	elapsed = now_ms - config->runtime.last_udp_send_ms;
	return (elapsed >= (uint64_t)config->scan.udp_send_gap_ms);
}

/**
 * @brief Check whether UDP in-flight limit allows a send.
 *
 * @param config Global nmap configuration.
 *
 * @return 1 if another UDP probe may be in flight, 0 otherwise.
 */
static int	udp_capacity_allows_send(t_nmap_config *config)
{
	if (config->scan.udp_max_in_flight <= 0)
		return (1);
	return (config->runtime.udp_in_flight_count
		< (size_t)config->scan.udp_max_in_flight);
}

/**
 * @brief Check whether the scheduler allows this probe now.
 *
 * @param config Global nmap configuration.
 * @param probe Probe considered for send.
 * @param now_ms Current timestamp.
 *
 * @return 1 if send is allowed, 0 otherwise.
 */
static int	scheduler_allows_probe(t_nmap_config *config,
		t_probe *probe, uint64_t now_ms)
{
	if (config->runtime.in_flight_count >= (size_t)config->scan.max_in_flight)
		return (0);
	if (!probe_is_udp(probe))
		return (1);
	if (!udp_capacity_allows_send(config))
		return (0);
	return (udp_gap_allows_send(config, now_ms));
}

/**
 * @brief Mark a probe as in flight immediately before sendto().
 *
 * @param config Global nmap configuration.
 * @param probe Probe that is about to be sent.
 * @param now_ms Current timestamp.
 *
 * @note The state is changed before sendto() so a very fast reply cannot be
 *       ignored as "not in flight yet".
 */
static void	mark_probe_in_flight(t_nmap_config *config,
		t_probe *probe, uint64_t now_ms)
{
	probe->sent_at_ms = now_ms;
	probe->state = PROBE_IN_FLIGHT;
	config->runtime.in_flight_count++;
	if (probe_is_udp(probe))
	{
		config->runtime.udp_in_flight_count++;
		config->runtime.last_udp_send_ms = now_ms;
	}
}

/**
 * @brief Undo in-flight accounting after sendto() failure.
 *
 * @param config Global nmap configuration.
 * @param probe Probe that failed.
 */
static void	mark_send_failed(t_nmap_config *config, t_probe *probe)
{
	probe->state = PROBE_DONE;
	probe->result = SCAN_RESULT_UNKNOWN;
	if (config->runtime.in_flight_count > 0)
		config->runtime.in_flight_count--;
	if (probe_is_udp(probe) && config->runtime.udp_in_flight_count > 0)
		config->runtime.udp_in_flight_count--;
	config->runtime.done_count++;
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
 *       UDP also respects udp_max_in_flight and udp_send_gap_ms.
 */
int	nmap_runtime_send_ready(t_nmap_config *config, int *exit_status)
{
	t_probe		*probe;
	uint64_t	now_ms;

	if (!config || config->scan.max_in_flight <= 0)
	{
		if (exit_status)
			*exit_status = 1;
		return (0);
	}
	while (config->runtime.next_to_send < config->runtime.probe_count)
	{
		probe = &config->runtime.probes[config->runtime.next_to_send];
		if (probe->state != PROBE_PENDING)
		{
			config->runtime.next_to_send++;
			continue ;
		}
		now_ms = get_time_ms();
		if (!scheduler_allows_probe(config, probe, now_ms))
			break ;
		mark_probe_in_flight(config, probe, now_ms);
		DEBUG_PROBE_SEND(probe);
		if (!send_probe(config, probe))
		{
			mark_send_failed(config, probe);
			if (exit_status)
				*exit_status = 1;
			return (0);
		}
		config->runtime.next_to_send++;
	}
	return (1);
}
