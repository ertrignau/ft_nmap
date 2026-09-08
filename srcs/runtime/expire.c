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

/** Return how many retransmissions this logical probe has already sent. */
static size_t	retries_used(const t_probe *probe)
{
	if (!probe || probe->attempts_sent == 0)
		return (0);
	return ((size_t)probe->attempts_sent - 1);
}

/** Move one expired probe back to scheduler-visible PENDING state. */
static void	retry_probe_locked(t_probe *probe)
{
	probe->state = PROBE_PENDING;
	probe->sent_at_ms = 0;
}

/**
 * @brief Hold one silent UDP probe until another retry proves a new level useful.
 */
static void	bench_probe_locked(t_nmap_config *config, t_probe *probe)
{
	probe->state = PROBE_BENCHED;
	probe->sent_at_ms = 0;
	config->runtime.benched_count++;
}

/** Finalize one still-unanswered probe using normal no-response semantics. */
static void	finalize_no_response_locked(t_nmap_config *config,
		t_probe *probe)
{
	if (probe->state == PROBE_BENCHED
		&& config->runtime.benched_count > 0)
		config->runtime.benched_count--;
	probe->state = PROBE_DONE;
	probe->result = nmap_classify_no_response(probe->scan_type);
	probe->reason = (t_scan_reason){0};
	probe->reason.kind = SCAN_REASON_NO_RESPONSE;
	config->runtime.done_count++;
	DEBUG_PROBE_RESULT(probe,
		"no matching response after retransmission policy");
}

/** Apply the original fixed retry policy to one TCP-family probe. */
static void	expire_tcp_probe_locked(t_nmap_config *config, t_probe *probe)
{
	size_t	hard_limit;

	hard_limit = 0;
	if (config->scan.retries > 0)
		hard_limit = (size_t)config->scan.retries;
	if (retries_used(probe) < hard_limit)
	{
		retry_probe_locked(probe);
		return ;
	}
	finalize_no_response_locked(config, probe);
}

/**
 * @brief Apply adaptive retry policy to one silent UDP probe.
 *
 * The configured retry count is a hard ceiling. Initially only retry #1 is
 * justified. Higher levels become schedulable only after an earlier retry
 * produced a useful network response on this same target.
 */
static void	expire_udp_probe_locked(t_nmap_config *config, t_probe *probe)
{
	size_t	used;
	size_t	allowed;
	size_t	hard_limit;

	used = retries_used(probe);
	allowed = nmap_timing_udp_allowed_retries_locked(config);
	hard_limit = config->runtime.timing.udp_retry_limit;
	if (used < allowed)
	{
		retry_probe_locked(probe);
		return ;
	}
	if (used < hard_limit)
	{
		bench_probe_locked(config, probe);
		return ;
	}
	finalize_no_response_locked(config, probe);
}

/**
 * @brief Apply timeout bookkeeping then route to TCP or UDP retry policy.
 */
static void	expire_probe_locked(t_nmap_config *config, t_probe *probe)
{
	remove_outstanding_count(config, probe);
	DEBUG_PROBE_TIMEOUT(probe);
	PROF_COUNT(NMAP_PROF_PACKET_TIMEOUT);
	if (nmap_probe_is_udp(probe))
		expire_udp_probe_locked(config, probe);
	else
		expire_tcp_probe_locked(config, probe);
	pthread_cond_broadcast(&config->runtime.probe_cond);
}

/**
 * @brief Return whether some non-benched probe can still change retry policy.
 *
 * PENDING work may still be sent. QUEUED/OUTSTANDING work may still produce a
 * useful response. If none exists, BENCHED probes cannot learn anything new
 * from the active scan and may safely receive their final no-response verdict.
 */
static int	has_retry_decision_source_locked(const t_nmap_config *config)
{
	size_t			i;
	t_probe_state	state;

	i = 0;
	while (i < config->runtime.probe_count)
	{
		state = config->runtime.probes[i].state;
		if (nmap_probe_is_udp(&config->runtime.probes[i])
			&& (state == PROBE_PENDING
				|| state == PROBE_QUEUED
				|| state == PROBE_OUTSTANDING))
			return (1);
		i++;
	}
	return (0);
}

/**
 * @brief Finalize a bench that can no longer be promoted by future evidence.
 */
static void	finalize_stalled_bench_locked(t_nmap_config *config)
{
	size_t	i;

	if (config->runtime.benched_count == 0
		|| has_retry_decision_source_locked(config))
		return ;
	i = 0;
	while (i < config->runtime.probe_count)
	{
		if (config->runtime.probes[i].state == PROBE_BENCHED)
			finalize_no_response_locked(config,
				&config->runtime.probes[i]);
		i++;
	}
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
	finalize_stalled_bench_locked(config);
	pthread_mutex_unlock(&config->runtime.lock);
	PROF_ADD(NMAP_PROF_EXPIRE, prof_start);
}
