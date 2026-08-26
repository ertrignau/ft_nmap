#include "runtime/runtime_internal.h"
#include "debug/debug.h"

#include <sys/time.h>

/** Return current wall-clock time in milliseconds. */
uint64_t	nmap_now_ms(void)
{
	struct timeval	tv;

	gettimeofday(&tv, NULL);
	return ((uint64_t)tv.tv_sec * 1000ULL
		+ (uint64_t)tv.tv_usec / 1000ULL);
}

/** Check whether one probe belongs to the UDP scan family. */
int	nmap_probe_is_udp(const t_probe *probe)
{
	return (probe && probe->scan_type == NMAP_SCAN_UDP);
}

/**
 * @brief Check whether an incoming reply may still complete this probe.
 *
 * @note PENDING and QUEUED remain matchable after at least one send so a late
 *       reply from an earlier attempt can still complete the logical probe.
 */
int	nmap_probe_can_match(const t_probe *probe)
{
	return (probe && probe->state != PROBE_DONE
		&& probe->attempts_sent > 0);
}

/**
 * @brief Atomically move one logical probe to DONE and maintain counters.
 *
 * @note The operation is idempotent for late duplicate replies.
 */
void	nmap_mark_probe_done(t_nmap_config *config, t_probe *probe,
		t_scan_result result, t_scan_reason reason, const char *debug_reason)
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
	probe->reason = reason;
	config->runtime.done_count++;
	pthread_mutex_unlock(&config->runtime.lock);
	DEBUG_PROBE_RESULT(probe, debug_reason);
}
