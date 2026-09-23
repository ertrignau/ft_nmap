
#include "runtime/runtime_internal.h"
#include "debug/debug.h"

#include <time.h>

/** Return current monotonic time in milliseconds. */
uint64_t	nmap_now_ms(void)
{
	struct timespec	ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return (0);
	return ((uint64_t)ts.tv_sec * 1000ULL
		+ (uint64_t)ts.tv_nsec / 1000000ULL);
}

/** Caller must have removed ONE QUEUED or OUTSTANDING reservation. */
void nmap_release_inflight(t_nmap_target_ctx *ctx)
{
    atomic_fetch_sub_explicit(&ctx->iface->inflight_jobs, 1,
        memory_order_release);
    atomic_fetch_sub_explicit(&ctx->engine->inflight_jobs, 1,
        memory_order_release);
}

/** Check whether one probe belongs to the UDP scan family. */
int	nmap_probe_is_udp(const t_probe *probe)
{
	return (probe && probe->scan_type == NMAP_SCAN_UDP);
}

/**
 * @brief Return whether the advanced scan core owns network concurrency.
 *
 * With --speedup 0, the main event loop controls windows, pacing and adaptive
 * timing. With --speedup N, N workers deliberately provide the only
 * concurrency limit and use fixed timeout/retry policy.
 */
int	nmap_runtime_uses_adaptive_core(const t_nmap_target_ctx *ctx)
{
	return (ctx && ctx->scan->thread_count == 0);
}

/**
 * @brief Check whether an incoming reply may still complete this probe.
 *
 * PENDING remains matchable after an earlier successful send. QUEUED remains
 * matchable after an earlier send as well, and also during the tiny interval
 * where the current generation has been claimed immediately before sendto().
 * A merely queued first attempt is not considered matchable yet.
 */
int	nmap_probe_can_match(const t_probe *probe)
{
	if (!probe || probe->state == PROBE_DONE)
		return (0);
	if (probe->attempts_sent > 0)
		return (1);
	return (probe->state == PROBE_QUEUED
		&& probe->sending_dispatch_id != 0
		&& probe->sending_dispatch_id == probe->dispatch_id);
}

/**
 * @brief Claim one exact QUEUED generation immediately before sendto().
 *
 * No network policy is decided here. The scheduler already selected this job;
 * this function only creates the atomic execution commit point used to reject
 * stale queue entries and to let a very fast reply match safely.
 */
int	nmap_runtime_begin_send(t_nmap_target_ctx *ctx, t_probe *probe,
		uint32_t dispatch_id, t_probe *snapshot)
{
	int	valid;

	if (!ctx || !probe)
		return (0);
	pthread_mutex_lock(&ctx->runtime.lock);
	valid = (probe->state == PROBE_QUEUED
			&& probe->dispatch_id == dispatch_id
			&& probe->sending_dispatch_id == 0);
	if (valid)
	{
		probe->sending_dispatch_id = dispatch_id;
		if (snapshot)
			*snapshot = *probe;
	}
	pthread_mutex_unlock(&ctx->runtime.lock);
	return (valid);
}

/** Remove one QUEUED probe from queue accounting while runtime.lock is held. */
static void	remove_queued_locked(t_nmap_target_ctx *ctx, const t_probe *probe)
{
	if (ctx->runtime.queued_count > 0)
		ctx->runtime.queued_count--;
	if (nmap_probe_is_udp(probe) && ctx->runtime.udp_queued_count > 0)
		ctx->runtime.udp_queued_count--;
}

/** Remove one BENCHED probe from bench accounting while runtime.lock is held. */
static void	remove_benched_locked(t_nmap_target_ctx *ctx)
{
	if (ctx->runtime.benched_count > 0)
		ctx->runtime.benched_count--;
}

/**
 * @brief Release every UDP probe waiting on the next justified retry level.
 *
 * Retry permission grows exactly one level at a time. Therefore every probe
 * currently BENCHED was stopped at the previously allowed level and becomes
 * schedulable when nmap_timing_note_reply_locked() reports one promotion.
 */
static void	release_benched_locked(t_nmap_target_ctx *ctx)
{
	size_t	i;

	i = 0;
	while (i < ctx->runtime.probe_count)
	{
		if (ctx->runtime.probes[i].state == PROBE_BENCHED)
		{
			ctx->runtime.probes[i].state = PROBE_PENDING;
			ctx->runtime.probes[i].sent_at_ms = 0;
			remove_benched_locked(ctx);
		}
		i++;
	}
}

/**
 * @brief Commit a successful sendto() for one claimed generation.
 *
 * If a late reply completed the logical probe while sendto() was executing,
 * the physical send is still accounted as having happened, but DONE is never
 * reopened and queued/outstanding counters are not touched a second time.
 */
void	nmap_runtime_complete_send(t_nmap_target_ctx *ctx, t_probe *probe,
		uint32_t dispatch_id, uint64_t sent_at_ms)
{
	if (!ctx || !probe)
		return ;
	pthread_mutex_lock(&ctx->runtime.lock);
	if (probe->dispatch_id != dispatch_id
		|| probe->sending_dispatch_id != dispatch_id)
	{
		pthread_mutex_unlock(&ctx->runtime.lock);
		return ;
	}
	probe->sending_dispatch_id = 0;
	if (probe->attempts_sent > 0)
		PROF_COUNT(NMAP_PROF_PROBE_RETRIED);
	probe->attempts_sent++;
	if (nmap_probe_is_udp(probe))
		ctx->runtime.last_udp_sent_ms = sent_at_ms;
	if (probe->state == PROBE_QUEUED)
	{
		remove_queued_locked(ctx, probe);
		ctx->runtime.outstanding_count++;
		if (nmap_probe_is_udp(probe))
			ctx->runtime.udp_outstanding_count++;
		probe->sent_at_ms = sent_at_ms;
		probe->deadline_ms = sent_at_ms
			+ nmap_timing_probe_timeout_ms(ctx, probe);
		probe->state = PROBE_OUTSTANDING;
	}
	pthread_mutex_unlock(&ctx->runtime.lock);
}

/**
 * @brief Record a failed sendto() for one claimed generation.
 *
 * A failure on the first physical attempt is always fatal. A retry can become
 * obsolete while sendto() is executing if a late reply from an earlier attempt
 * completes the probe; in that case the already-valid network result wins and
 * the obsolete retry failure does not poison the whole target.
 */
int	nmap_runtime_fail_send(t_nmap_target_ctx *ctx, t_probe *probe,
		uint32_t dispatch_id)
{
	t_scan_reason	reason;
    t_probe         debug_snapshot;
	int				fatal;
	int				marked_done;

	if (!ctx || !probe)
		return (0);
	fatal = 0;
	marked_done = 0;
	pthread_mutex_lock(&ctx->runtime.lock);
	if (probe->dispatch_id == dispatch_id
		&& probe->sending_dispatch_id == dispatch_id)
	{
		probe->sending_dispatch_id = 0;
		if (probe->state == PROBE_DONE)
			fatal = (probe->attempts_sent == 0);
		else if (probe->state == PROBE_QUEUED)
		{
			remove_queued_locked(ctx, probe);
            nmap_release_inflight(ctx);
			reason = (t_scan_reason){0};
			reason.kind = SCAN_REASON_SEND_ERROR;
			probe->state = PROBE_DONE;
			probe->result = SCAN_RESULT_UNKNOWN;
			probe->reason = reason;
			ctx->runtime.done_count++;
			fatal = 1;
            debug_snapshot = *probe;
			marked_done = 1;
		}
	}
	pthread_mutex_unlock(&ctx->runtime.lock);
	if (marked_done)
		DEBUG_PROBE_RESULT(&debug_snapshot, "send failure");
	return (fatal);
}

/**
 * @brief Atomically move one logical probe to DONE and maintain counters.
 *
 * @note The operation is idempotent for late duplicate replies. If a worker
 *       already claimed the current QUEUED generation, the physical send may
 *       still finish, but its later commit cannot reopen this DONE probe.
 *
 * A successful UDP retry may justify exactly one additional retry level.
 * BENCHED probes are released only after the current replying probe has been
 * removed from its previous lifecycle accounting and committed as DONE.
 */
void	nmap_mark_probe_done(t_nmap_target_ctx *ctx, t_probe *probe,
		t_scan_result result, t_scan_reason reason, const char *debug_reason)
{
	t_probe_state	old_state;
    t_probe         debug_snapshot;
	int				retry_level_increased;

	if (!ctx || !probe)
		return ;
	pthread_mutex_lock(&ctx->runtime.lock);
	if (probe->state == PROBE_DONE)
	{
		pthread_mutex_unlock(&ctx->runtime.lock);
		return ;
	}
	old_state = probe->state;
	retry_level_increased = 0;
	if (reason.kind == SCAN_REASON_TCP
		|| reason.kind == SCAN_REASON_UDP_REPLY
		|| reason.kind == SCAN_REASON_ICMP)
	{
		retry_level_increased = nmap_timing_note_reply_locked(
				ctx, probe, &reason, nmap_now_ms());
	}
	if (old_state == PROBE_QUEUED)
    {
		remove_queued_locked(ctx, probe);
        nmap_release_inflight(ctx);
    }
	else if (old_state == PROBE_OUTSTANDING)
	{
		if (ctx->runtime.outstanding_count > 0)
			ctx->runtime.outstanding_count--;
        nmap_release_inflight(ctx);
		if (nmap_probe_is_udp(probe)
			&& ctx->runtime.udp_outstanding_count > 0)
			ctx->runtime.udp_outstanding_count--;
	}
	else if (old_state == PROBE_BENCHED)
		remove_benched_locked(ctx);
	probe->state = PROBE_DONE;
	probe->result = result;
	probe->reason = reason;
	ctx->runtime.done_count++;
	if (retry_level_increased)
		release_benched_locked(ctx);
    debug_snapshot = *probe;
	pthread_cond_broadcast(&ctx->runtime.probe_cond);
	pthread_mutex_unlock(&ctx->runtime.lock);
	DEBUG_PROBE_RESULT(&debug_snapshot, debug_reason);
}
