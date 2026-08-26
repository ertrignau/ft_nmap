#include "runtime/runtime_internal.h"
#include "debug/debug.h"

#include <sys/time.h>

/**
 * @brief Return current wall-clock time in milliseconds.
 */
uint64_t	nmap_now_ms(void)
{
	struct timeval	tv;

	gettimeofday(&tv, NULL);
	return ((uint64_t)tv.tv_sec * 1000ULL
		+ (uint64_t)tv.tv_usec / 1000ULL);
}

/**
 * @brief Check whether one probe belongs to the UDP scan family.
 */
int	nmap_probe_is_udp(const t_probe *probe)
{
	return (probe && probe->scan_type == NMAP_SCAN_UDP);
}

/**
 * @brief Check whether an incoming reply may still complete this probe.
 *
 * @note PENDING and QUEUED are intentionally matchable after at least one send.
 *       This allows a late reply from the previous attempt to win while a
 *       retransmission is pending or already queued.
 */
int	nmap_probe_can_match(const t_probe *probe)
{
	return (probe && probe->state != PROBE_DONE
		&& probe->attempts_sent > 0);
}

/**
 * @brief Atomically move one logical probe to DONE and maintain counters.
 *
 * @param config Global scan state.
 * @param probe Probe to finalize.
 * @param result Semantic final result.
 * @param reason Debug reason string.
 *
 * @note This function is idempotent with respect to late duplicate replies: a
 *       probe already in DONE is left untouched.
 */
void	nmap_mark_probe_done(t_nmap_config *config, t_probe *probe,
		t_scan_result result, const char *reason)
{
	t_probe_state	old_state;

	if (!config || !probe)
		return ;
	pthread_mutex_lock(&config->runtime.lock);
	if (probe->state == PROBE_DONE)
	{
		pthread_mutex_unlock(&config->runtime.lock);
		return ;
	}
	old_state = probe->state;
	if (old_state == PROBE_QUEUED)
	{
		if (config->runtime.queued_count > 0)
			config->runtime.queued_count--;
		if (nmap_probe_is_udp(probe)
			&& config->runtime.udp_queued_count > 0)
			config->runtime.udp_queued_count--;
	}
	else if (old_state == PROBE_OUTSTANDING)
	{
		if (config->runtime.outstanding_count > 0)
			config->runtime.outstanding_count--;
		if (nmap_probe_is_udp(probe)
			&& config->runtime.udp_outstanding_count > 0)
			config->runtime.udp_outstanding_count--;
	}
	probe->state = PROBE_DONE;
	probe->result = result;
	config->runtime.done_count++;
	pthread_mutex_unlock(&config->runtime.lock);
	DEBUG_PROBE_RESULT(probe, reason);
}
