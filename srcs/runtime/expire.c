
#include "config.h"
#include "debug/debug.h"
#include "runtime/runtime_internal.h"

/** Check whether one OUTSTANDING probe reached its current deadline. */
static int	probe_expired(const t_nmap_config *config,
		const t_probe *probe, uint64_t now_ms)
{
	uint64_t	timeout_ms;
	uint64_t	elapsed;

	if (probe->state != PROBE_OUTSTANDING)
		return (0);
	timeout_ms = nmap_timing_probe_timeout_ms(config, probe);
	if (timeout_ms == 0)
		return (1);
	elapsed = now_ms - probe->sent_at_ms;
	return (elapsed >= timeout_ms);
}

/** Remove one probe from outstanding accounting while runtime.lock is held. */
static void	remove_outstanding_count(t_nmap_config *config,
		const t_probe *probe)
{
	if (config->runtime.outstanding_count > 0)
		config->runtime.outstanding_count--;
	if (nmap_probe_is_udp(probe)
		&& config->runtime.udp_outstanding_count > 0)
		config->runtime.udp_outstanding_count--;
}

/**
 * @brief Apply retransmission policy or final no-response classification.
 *
 * @note retries counts additional successful sends. With retries=1, the first
 *       successful attempt times out back to PENDING; the second successful
 *       attempt times out to the final no-response result.
 */
static void	expire_probe_locked(t_nmap_config *config, t_probe *probe)
{
	t_scan_result	result;

	remove_outstanding_count(config, probe);
	DEBUG_PROBE_TIMEOUT(probe);
	PROF_COUNT(NMAP_PROF_PACKET_TIMEOUT);
	if (probe->attempts_sent <= (uint8_t)config->scan.retries)
	{
		probe->state = PROBE_PENDING;
		probe->sent_at_ms = 0;
		PROF_COUNT(NMAP_PROF_PROBE_RETRIED);
		return ;
	}
	result = nmap_classify_no_response(probe->scan_type);
	probe->state = PROBE_DONE;
	probe->result = result;
	probe->reason = (t_scan_reason){0};
	probe->reason.kind = SCAN_REASON_NO_RESPONSE;
	config->runtime.done_count++;
	DEBUG_PROBE_RESULT(probe,
		"no matching response after retransmission policy");
}

/**
 * @brief Expire every probe whose current successful attempt reached deadline.
 */
void	nmap_runtime_expire_probes(t_nmap_config *config)
{
	size_t		i;
	uint64_t	now_ms;
	uint64_t	prof_start;

	if (!config || !config->runtime.probes)
		return ;
	prof_start = PROF_START();
	now_ms = nmap_now_ms();
	pthread_mutex_lock(&config->runtime.lock);
	i = 0;
	while (i < config->runtime.probe_count)
	{
		if (probe_expired(config, &config->runtime.probes[i], now_ms))
			expire_probe_locked(config, &config->runtime.probes[i]);
		i++;
	}
	pthread_mutex_unlock(&config->runtime.lock);
	PROF_ADD(NMAP_PROF_EXPIRE, prof_start);
}
