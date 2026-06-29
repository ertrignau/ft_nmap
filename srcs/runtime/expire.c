#include "config.h"
#include "debug/debug.h"
#include "runtime/worker.h"

#include <sys/time.h>

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
 * @brief Return the scan result produced by a timeout.
 *
 * @param scan_type Scan type stored in the probe.
 *
 * @return Timeout result for this scan type.
 *
 * @note Timeout does not mean the same thing for all scan types. SYN and ACK
 *       timeouts mean filtered, while NULL/FIN/XMAS/UDP timeouts are ambiguous.
 */
static t_scan_result	get_timeout_result(uint32_t scan_type)
{
	if (scan_type == NMAP_SCAN_SYN)
		return (SCAN_RESULT_FILTERED);
	if (scan_type == NMAP_SCAN_ACK)
		return (SCAN_RESULT_FILTERED);
	if (scan_type == NMAP_SCAN_NULL)
		return (SCAN_RESULT_OPEN_FILTERED);
	if (scan_type == NMAP_SCAN_FIN)
		return (SCAN_RESULT_OPEN_FILTERED);
	if (scan_type == NMAP_SCAN_XMAS)
		return (SCAN_RESULT_OPEN_FILTERED);
	if (scan_type == NMAP_SCAN_UDP)
		return (SCAN_RESULT_OPEN_FILTERED);
	return (SCAN_RESULT_UNKNOWN);
}

/**
 * @brief Return the timeout for a specific probe.
 *
 * @param config Global nmap configuration.
 * @param probe Probe to inspect.
 *
 * @return Timeout in milliseconds.
 */
static int	get_probe_timeout_ms(t_nmap_config *config, t_probe *probe)
{
	if (probe->scan_type == NMAP_SCAN_UDP)
		return (config->scan.udp_timeout_ms);
	return (config->scan.tcp_timeout_ms);
}

/**
 * @brief Check whether an in-flight probe has expired.
 *
 * @param probe Runtime probe to check.
 * @param now_ms Current timestamp in milliseconds.
 * @param timeout_ms Probe timeout in milliseconds.
 *
 * @return 1 if the probe expired, 0 otherwise.
 */
static int	probe_has_expired(t_probe *probe, uint64_t now_ms, int timeout_ms)
{
	uint64_t	elapsed_ms;

	if (probe->state != PROBE_IN_FLIGHT)
		return (0);
	if (timeout_ms < 0)
		timeout_ms = 0;
	elapsed_ms = now_ms - probe->sent_at_ms;
	return (elapsed_ms >= (uint64_t)timeout_ms);
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
 * @brief Mark one in-flight probe as done after timeout.
 *
 * @param config Global nmap configuration.
 * @param probe Runtime probe to expire.
 */
static void	expire_probe(t_nmap_config *config, t_probe *probe)
{
	probe->result = get_timeout_result(probe->scan_type);
	probe->state = PROBE_DONE;
	if (config->runtime.in_flight_count > 0)
		config->runtime.in_flight_count--;
	if (probe_is_udp(probe) && config->runtime.udp_in_flight_count > 0)
		config->runtime.udp_in_flight_count--;
	nmap_sender_note_probe_done_locked(config, probe);
	config->runtime.done_count++;
	DEBUG_PROBE_TIMEOUT(probe);
	DEBUG_PROBE_RESULT(probe, "timeout");
	PROF_COUNT(NMAP_PROF_PACKET_TIMEOUT);
}

/**
 * @brief Expire all in-flight probes that reached timeout.
 *
 * @param config Global nmap configuration.
 *
 * @note This function does not block and does not read packets. It only updates
 *       runtime state from IN_FLIGHT to DONE when timeout is reached.
 */
void	nmap_runtime_expire_probes(t_nmap_config *config)
{
	size_t		i;
	uint64_t	now_ms;
	uint64_t	prof_start;

	if (!config || !config->runtime.probes)
		return ;
	prof_start = PROF_START();
	now_ms = get_time_ms();
	pthread_mutex_lock(&config->sender_pool.runtime_lock);
	i = 0;
	while (i < config->runtime.probe_count)
	{
		if (probe_has_expired(&config->runtime.probes[i], now_ms,
				get_probe_timeout_ms(config, &config->runtime.probes[i])))
			expire_probe(config, &config->runtime.probes[i]);
		i++;
	}
	pthread_mutex_unlock(&config->sender_pool.runtime_lock);
	PROF_ADD(NMAP_PROF_EXPIRE, prof_start);
}
