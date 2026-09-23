#include "config.h"
#include "debug/debug.h"
#include "runtime/runtime_internal.h"

/** Check whether one OUTSTANDING probe reached its current deadline. */
static int	probe_expired(const t_probe *probe, uint64_t now_ms)
{
	return (probe->state == PROBE_OUTSTANDING
		&& now_ms >= probe->deadline_ms);
}

/** Remove one probe from outstanding accounting while runtime.lock is held. */
static void	remove_outstanding_count(t_nmap_target_ctx *ctx,
		const t_probe *probe)
{
	if (ctx->runtime.outstanding_count > 0)
		ctx->runtime.outstanding_count--;
    nmap_release_inflight(ctx);
	if (nmap_probe_is_udp(probe)
		&& ctx->runtime.udp_outstanding_count > 0)
		ctx->runtime.udp_outstanding_count--;
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
static void	bench_probe_locked(t_nmap_target_ctx *ctx, t_probe *probe)
{
	probe->state = PROBE_BENCHED;
	probe->sent_at_ms = 0;
	ctx->runtime.benched_count++;
}

/** Finalize one still-unanswered probe using normal no-response semantics. */
static void	finalize_no_response_locked(t_nmap_target_ctx *ctx,
		t_probe *probe)
{
	if (probe->state == PROBE_BENCHED
		&& ctx->runtime.benched_count > 0)
		ctx->runtime.benched_count--;
	probe->state = PROBE_DONE;
	probe->result = nmap_classify_no_response(probe->scan_type);
	probe->reason = (t_scan_reason){0};
	probe->reason.kind = SCAN_REASON_NO_RESPONSE;
	ctx->runtime.done_count++;
	DEBUG_PROBE_RESULT(probe,
		"no matching response after retransmission policy");
}

/**
 * @brief Apply a fixed retry count without adaptive retry learning.
 *
 * This policy is used by TCP in the adaptive core and by every protocol in
 * --speedup mode.
 */
static void	expire_fixed_retry_probe_locked(t_nmap_target_ctx *ctx,
		t_probe *probe)
{
	size_t	hard_limit;

	hard_limit = 0;
	if (ctx->scan->retries > 0)
		hard_limit = (size_t)ctx->scan->retries;
	if (retries_used(probe) < hard_limit)
	{
		retry_probe_locked(probe);
		return ;
	}
	finalize_no_response_locked(ctx, probe);
}

/**
 * @brief Apply adaptive retry policy to one silent UDP probe.
 *
 * The configured retry count is a hard ceiling. Initially only retry #1 is
 * justified. Higher levels become schedulable only after an earlier retry
 * produced a useful network response on this same target.
 */
static void	expire_udp_probe_locked(t_nmap_target_ctx *ctx, t_probe *probe)
{
	size_t	used;
	size_t	allowed;
	size_t	hard_limit;

	used = retries_used(probe);
	allowed = nmap_timing_udp_allowed_retries_locked(ctx);
	hard_limit = ctx->runtime.timing.udp_retry_limit;
	if (used < allowed)
	{
		retry_probe_locked(probe);
		return ;
	}
	if (used < hard_limit)
	{
		bench_probe_locked(ctx, probe);
		return ;
	}
	finalize_no_response_locked(ctx, probe);
}

/**
 * @brief Apply timeout bookkeeping then route to TCP or UDP retry policy.
 */
static void	expire_probe_locked(t_nmap_target_ctx *ctx, t_probe *probe)
{
	remove_outstanding_count(ctx, probe);
	DEBUG_PROBE_TIMEOUT(probe);
	PROF_COUNT(NMAP_PROF_PACKET_TIMEOUT);
	if (!nmap_runtime_uses_adaptive_core(ctx))
	{
		expire_fixed_retry_probe_locked(ctx, probe);
	}
	else if (nmap_probe_is_udp(probe))
	{
		expire_udp_probe_locked(ctx, probe);
	}
	else
	{
		expire_fixed_retry_probe_locked(ctx, probe);
	}
	pthread_cond_broadcast(&ctx->runtime.probe_cond);
}

/**
 * @brief Return whether some non-benched probe can still change retry policy.
 *
 * PENDING work may still be sent. QUEUED/OUTSTANDING work may still produce a
 * useful response. If none exists, BENCHED probes cannot learn anything new
 * from the active scan and may safely receive their final no-response verdict.
 */
static int	has_retry_decision_source_locked(const t_nmap_target_ctx *ctx)
{
	size_t			i;
	t_probe_state	state;

	i = 0;
	while (i < ctx->runtime.probe_count)
	{
		state = ctx->runtime.probes[i].state;
		if (nmap_probe_is_udp(&ctx->runtime.probes[i])
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
static void	finalize_stalled_bench_locked(t_nmap_target_ctx *ctx)
{
	size_t	i;

	if (!nmap_runtime_uses_adaptive_core(ctx)
		|| ctx->runtime.benched_count == 0
		|| has_retry_decision_source_locked(ctx))
		return ;
	i = 0;
	while (i < ctx->runtime.probe_count)
	{
		if (ctx->runtime.probes[i].state == PROBE_BENCHED)
			finalize_no_response_locked(ctx,
				&ctx->runtime.probes[i]);
		i++;
	}
}

/**
 * @brief Expire every probe whose current successful attempt reached deadline.
 */
void	nmap_runtime_expire_probes(t_nmap_target_ctx *ctx)
{
	size_t		i;
	uint64_t	now_ms;
	uint64_t	prof_start;

	if (!ctx || !ctx->runtime.probes)
		return ;
	prof_start = PROF_START();
	now_ms = nmap_now_ms();
	pthread_mutex_lock(&ctx->runtime.lock);
	i = 0;
	while (i < ctx->runtime.probe_count)
	{
		if (probe_expired(&ctx->runtime.probes[i], now_ms))
			expire_probe_locked(ctx, &ctx->runtime.probes[i]);
		i++;
	}
	finalize_stalled_bench_locked(ctx);
	pthread_mutex_unlock(&ctx->runtime.lock);
	PROF_ADD(NMAP_PROF_EXPIRE, prof_start);
}
