#!/usr/bin/env python3

from pathlib import Path
import sys


RUNTIME_H = Path("inc/runtime.h")
INTERNAL_H = Path("srcs/runtime/runtime_internal.h")
COMMON_C = Path("srcs/runtime/common.c")
EXPIRE_C = Path("srcs/runtime/expire.c")
TIMING_C = Path("srcs/runtime/timing.c")


TIMING_SOURCE = r'''#include "runtime/runtime_internal.h"

#define NMAP_RTO_MIN_MS 100ULL

#define NMAP_UDP_WINDOW_RECOVERY_REPLIES 8

#define NMAP_UDP_BACKOFF_INITIAL_GAP_MS 50ULL
#define NMAP_UDP_BACKOFF_MAX_GAP_MS 1000ULL

/** Return the smaller of two size_t values. */
static size_t	min_size(size_t a, size_t b)
{
	if (a < b)
		return (a);
	return (b);
}

/** Clamp one RTO to the target timing limits. */
static uint64_t	clamp_rto(const t_nmap_timing *timing, uint64_t rto)
{
	if (rto < timing->rto_min_ms)
		return (timing->rto_min_ms);
	if (rto > timing->rto_max_ms)
		return (timing->rto_max_ms);
	return (rto);
}

/** Return the currently justified number of UDP retransmissions. */
size_t	nmap_timing_udp_allowed_retries_locked(
		const t_nmap_config *config)
{
	const t_nmap_timing	*timing;
	size_t				allowed;

	if (!config)
		return (0);
	timing = &config->runtime.timing;
	if (timing->udp_retry_limit == 0)
		return (0);
	allowed = timing->udp_max_successful_retry + 1;
	if (allowed > timing->udp_retry_limit)
		allowed = timing->udp_retry_limit;
	return (allowed);
}

/**
 * @brief Initialize target-local adaptive timing policy.
 *
 * TCP starts with the configured timeout as a conservative RTO ceiling.
 * UDP starts with at most one justified retransmission; higher retry levels
 * must be proven useful by successful replies from earlier retry levels.
 */
void	nmap_timing_init(t_nmap_config *config)
{
	t_nmap_timing	*timing;
	size_t			global_window;
	size_t			udp_window;

	if (!config)
		return ;
	timing = &config->runtime.timing;
	timing->rto_max_ms = (uint64_t)config->scan.tcp_timeout_ms;
	if (timing->rto_max_ms == 0)
		timing->rto_max_ms = NMAP_RTO_MIN_MS;
	timing->rto_min_ms = NMAP_RTO_MIN_MS;
	if (timing->rto_max_ms < timing->rto_min_ms)
		timing->rto_min_ms = timing->rto_max_ms;
	timing->rto_ms = timing->rto_max_ms;

	global_window = (size_t)config->scan.window_size;
	udp_window = (size_t)config->scan.udp_window_size;
	if (global_window == 0)
		global_window = 1;
	if (udp_window == 0)
		udp_window = 1;
	timing->udp_window_min = 1;
	timing->udp_window_max = min_size(global_window, udp_window);
	if (timing->udp_window_max == 0)
		timing->udp_window_max = 1;
	timing->udp_window = timing->udp_window_max;

	if (config->scan.udp_send_gap_ms > 0)
		timing->udp_send_gap_ms =
			(uint64_t)config->scan.udp_send_gap_ms;
	timing->udp_send_gap_max_ms = NMAP_UDP_BACKOFF_MAX_GAP_MS;
	if (timing->udp_send_gap_ms > timing->udp_send_gap_max_ms)
		timing->udp_send_gap_max_ms = timing->udp_send_gap_ms;

	if (config->scan.retries > 0)
		timing->udp_retry_limit = (size_t)config->scan.retries;
}

/**
 * @brief Return the timeout applying to one currently outstanding probe.
 *
 * TCP-family scans use the target adaptive RTO after the first valid RTT
 * sample. UDP deliberately keeps the configured UDP timeout.
 */
uint64_t	nmap_timing_probe_timeout_ms(const t_nmap_config *config,
		const t_probe *probe)
{
	if (!config || !probe)
		return (0);
	if (nmap_probe_is_udp(probe))
		return ((uint64_t)config->scan.udp_timeout_ms);
	if (!config->runtime.timing.rtt_valid)
		return ((uint64_t)config->scan.tcp_timeout_ms);
	return (config->runtime.timing.rto_ms);
}

/**
 * @brief Feed one unambiguous RTT sample into the target estimator.
 *
 * Formula:
 *   SRTT   <- SRTT + (sample - SRTT) / 8
 *   RTTVAR <- RTTVAR + (|sample - SRTT| - RTTVAR) / 4
 *   RTO    <- SRTT + 4 * RTTVAR
 *
 * Integer arithmetic is written in weighted-average form to avoid signed
 * intermediate values.
 */
static void	update_rtt(t_nmap_timing *timing, uint64_t sample_ms)
{
	uint64_t	delta;
	uint64_t	next_rto;

	if (sample_ms == 0)
		sample_ms = 1;
	if (!timing->rtt_valid)
	{
		timing->srtt_ms = sample_ms;
		timing->rttvar_ms = sample_ms / 2;
		if (timing->rttvar_ms == 0)
			timing->rttvar_ms = 1;
		timing->rtt_valid = 1;
	}
	else
	{
		if (sample_ms > timing->srtt_ms)
			delta = sample_ms - timing->srtt_ms;
		else
			delta = timing->srtt_ms - sample_ms;
		timing->rttvar_ms =
			(3 * timing->rttvar_ms + delta) / 4;
		timing->srtt_ms =
			(7 * timing->srtt_ms + sample_ms) / 8;
		if (timing->rttvar_ms == 0)
			timing->rttvar_ms = 1;
	}
	next_rto = timing->srtt_ms + 4 * timing->rttvar_ms;
	timing->rto_ms = clamp_rto(timing, next_rto);
}

/**
 * @brief Increase TCP RTO after a reply recovered only after retransmission.
 *
 * Such a reply is intentionally not used as an RTT sample because it is
 * ambiguous which transmitted attempt caused it.
 */
static void	backoff_rto(t_nmap_timing *timing)
{
	uint64_t	next;

	if (!timing->rtt_valid
		|| timing->rto_ms >= timing->rto_max_ms)
		return ;
	if (timing->rto_ms > timing->rto_max_ms / 2)
		next = timing->rto_max_ms;
	else
		next = timing->rto_ms * 2;
	timing->rto_ms = clamp_rto(timing, next);
}

/** Set a minimum UDP send gap without reducing an existing larger gap. */
static void	ensure_udp_gap(t_nmap_timing *timing, uint64_t minimum)
{
	if (minimum > timing->udp_send_gap_max_ms)
		minimum = timing->udp_send_gap_max_ms;
	if (timing->udp_send_gap_ms < minimum)
		timing->udp_send_gap_ms = minimum;
}

/**
 * @brief React to an ICMP response that was recovered only after a UDP retry.
 *
 * The first observation stops zero-gap bursts. The second observation confirms
 * the pattern, halves UDP parallelism once, and doubles the gap. Further
 * observations keep doubling the gap up to the configured ceiling.
 */
static void	note_udp_icmp_retry_recovery(t_nmap_timing *timing)
{
	size_t		next_window;
	uint64_t	next_gap;

	timing->udp_clean_replies = 0;
	timing->udp_rate_limit_evidence++;
	if (timing->udp_rate_limit_evidence == 1)
	{
		ensure_udp_gap(timing, NMAP_UDP_BACKOFF_INITIAL_GAP_MS);
		return ;
	}
	if (timing->udp_rate_limit_evidence == 2)
	{
		next_window = (timing->udp_window + 1) / 2;
		if (next_window < timing->udp_window_min)
			next_window = timing->udp_window_min;
		timing->udp_window = next_window;
	}
	if (timing->udp_send_gap_ms == 0)
		next_gap = NMAP_UDP_BACKOFF_INITIAL_GAP_MS;
	else if (timing->udp_send_gap_ms
		> timing->udp_send_gap_max_ms / 2)
		next_gap = timing->udp_send_gap_max_ms;
	else
		next_gap = timing->udp_send_gap_ms * 2;
	if (next_gap > timing->udp_send_gap_max_ms)
		next_gap = timing->udp_send_gap_max_ms;
	timing->udp_send_gap_ms = next_gap;
}

/**
 * @brief Slowly restore UDP window capacity after clean first-attempt replies.
 *
 * The pacing delay deliberately never decreases during one target scan.
 */
static void	note_clean_udp_reply(t_nmap_timing *timing)
{
	timing->udp_clean_replies++;
	if (timing->udp_clean_replies
		< NMAP_UDP_WINDOW_RECOVERY_REPLIES)
		return ;
	if (timing->udp_window < timing->udp_window_max)
		timing->udp_window++;
	timing->udp_clean_replies = 0;
}

/**
 * @brief Record that one concrete UDP retry level produced useful evidence.
 *
 * A success after retry N justifies trying retry N+1 on still-silent probes,
 * never more than one level at a time and never beyond udp_retry_limit.
 *
 * @return 1 when the currently allowed retry level increased.
 */
static int	note_udp_retry_success(t_nmap_timing *timing,
		const t_probe *probe)
{
	size_t	before;
	size_t	retry_number;
	size_t	after;

	if (probe->attempts_sent <= 1)
		return (0);
	before = timing->udp_max_successful_retry + 1;
	if (before > timing->udp_retry_limit)
		before = timing->udp_retry_limit;
	retry_number = (size_t)probe->attempts_sent - 1;
	if (retry_number > timing->udp_retry_limit)
		retry_number = timing->udp_retry_limit;
	if (retry_number > timing->udp_max_successful_retry)
		timing->udp_max_successful_retry = retry_number;
	after = timing->udp_max_successful_retry + 1;
	if (after > timing->udp_retry_limit)
		after = timing->udp_retry_limit;
	return (after > before);
}

/**
 * @brief Update target timing from one accepted network response.
 *
 * @note runtime.lock must already be held.
 *
 * Karn rule:
 *   attempts_sent == 1 and sent_at_ms != 0 -> unambiguous RTT sample.
 *   attempts_sent > 1                      -> never update RTT.
 *
 * For UDP, any useful retry may justify one additional retry level, while
 * only an ICMP recovered after retry is treated as rate-limit evidence.
 *
 * @return 1 when UDP retry policy expanded and BENCHED probes may be released.
 */
int	nmap_timing_note_reply_locked(t_nmap_config *config,
		const t_probe *probe, const t_scan_reason *reason,
		uint64_t now_ms)
{
	t_nmap_timing	*timing;
	uint64_t		sample_ms;
	int				retry_level_increased;
	int				first_attempt_sample;

	if (!config || !probe || !reason || probe->attempts_sent == 0)
		return (0);
	timing = &config->runtime.timing;
	retry_level_increased = 0;
	first_attempt_sample = (probe->attempts_sent == 1
			&& probe->sent_at_ms != 0
			&& now_ms >= probe->sent_at_ms);
	if (first_attempt_sample)
	{
		sample_ms = now_ms - probe->sent_at_ms;
		update_rtt(timing, sample_ms);
	}
	if (nmap_probe_is_udp(probe))
	{
		if (probe->attempts_sent > 1)
		{
			retry_level_increased =
				note_udp_retry_success(timing, probe);
			timing->udp_clean_replies = 0;
			if (reason->kind == SCAN_REASON_ICMP)
				note_udp_icmp_retry_recovery(timing);
		}
		else if (first_attempt_sample)
			note_clean_udp_reply(timing);
	}
	else if (probe->attempts_sent > 1)
		backoff_rto(timing);
	return (retry_level_increased);
}
'''


EXPIRE_SOURCE = r'''#include "config.h"
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
	PROF_COUNT(NMAP_PROF_PROBE_RETRIED);
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
		if (state == PROBE_PENDING
			|| state == PROBE_QUEUED
			|| state == PROBE_OUTSTANDING)
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
'''


BENCH_HELPERS = r'''/** Remove one BENCHED probe from bench accounting while runtime.lock is held. */
static void	remove_benched_locked(t_nmap_config *config)
{
	if (config->runtime.benched_count > 0)
		config->runtime.benched_count--;
}

/**
 * @brief Release every UDP probe waiting on the next justified retry level.
 *
 * Retry permission grows exactly one level at a time. Therefore every probe
 * currently BENCHED was stopped at the previously allowed level and becomes
 * schedulable when nmap_timing_note_reply_locked() reports one promotion.
 */
static void	release_benched_locked(t_nmap_config *config)
{
	size_t	i;

	i = 0;
	while (i < config->runtime.probe_count)
	{
		if (config->runtime.probes[i].state == PROBE_BENCHED)
		{
			config->runtime.probes[i].state = PROBE_PENDING;
			config->runtime.probes[i].sent_at_ms = 0;
			remove_benched_locked(config);
			PROF_COUNT(NMAP_PROF_PROBE_RETRIED);
		}
		i++;
	}
}

'''


MARK_DONE_SOURCE = r'''/**
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
void	nmap_mark_probe_done(t_nmap_config *config, t_probe *probe,
		t_scan_result result, t_scan_reason reason, const char *debug_reason)
{
	t_probe_state	old_state;
	int				retry_level_increased;

	if (!config || !probe)
		return ;
	pthread_mutex_lock(&config->runtime.lock);
	if (probe->state == PROBE_DONE)
	{
		pthread_mutex_unlock(&config->runtime.lock);
		return ;
	}
	old_state = probe->state;
	retry_level_increased = 0;
	if (reason.kind == SCAN_REASON_TCP
		|| reason.kind == SCAN_REASON_UDP_REPLY
		|| reason.kind == SCAN_REASON_ICMP)
	{
		retry_level_increased = nmap_timing_note_reply_locked(
				config, probe, &reason, nmap_now_ms());
	}
	if (old_state == PROBE_QUEUED)
		remove_queued_locked(config, probe);
	else if (old_state == PROBE_OUTSTANDING)
	{
		if (config->runtime.outstanding_count > 0)
			config->runtime.outstanding_count--;
		if (nmap_probe_is_udp(probe)
			&& config->runtime.udp_outstanding_count > 0)
			config->runtime.udp_outstanding_count--;
	}
	else if (old_state == PROBE_BENCHED)
		remove_benched_locked(config);
	probe->state = PROBE_DONE;
	probe->result = result;
	probe->reason = reason;
	config->runtime.done_count++;
	if (retry_level_increased)
		release_benched_locked(config);
	pthread_mutex_unlock(&config->runtime.lock);
	DEBUG_PROBE_RESULT(probe, debug_reason);
}
'''


def fail(message):
    print(f"tot.py: {message}", file=sys.stderr)
    raise SystemExit(1)


def read(path):
    if not path.exists():
        fail(f"{path}: fichier introuvable")
    return path.read_text(encoding="utf-8")


def replace_once(text, old, new, path):
    count = text.count(old)
    if count != 1:
        fail(f"{path}: remplacement ambigu ({count} occurrences)")
    return text.replace(old, new, 1)


def patch_runtime_h(text):
    old_state = """ * PENDING      ready for the scheduler.
 * QUEUED       one dispatch generation is reserved; it may still be waiting
 *              in the sender queue or currently executing sendto().
 * OUTSTANDING  sendto() completed successfully and its timeout clock is live.
 * DONE         final scan result has been produced.
 *
 * @note A logical probe survives retransmissions. A retry does not allocate a
 *       second probe object; the same probe returns to PENDING.
 */
typedef enum e_probe_state
{
\tPROBE_PENDING = 0,
\tPROBE_QUEUED,
\tPROBE_OUTSTANDING,
\tPROBE_DONE
}\tt_probe_state;
"""
    new_state = """ * PENDING      ready for the scheduler.
 * QUEUED       one dispatch generation is reserved; it may still be waiting
 *              in the sender queue or currently executing sendto().
 * OUTSTANDING  sendto() completed successfully and its timeout clock is live.
 * BENCHED      UDP probe has exhausted the currently justified retry level.
 *              It remains matchable but is not schedulable until another
 *              successful retry proves that one more level is useful.
 * DONE         final scan result has been produced.
 *
 * @note A logical probe survives retransmissions. A retry does not allocate a
 *       second probe object; the same probe returns to PENDING.
 */
typedef enum e_probe_state
{
\tPROBE_PENDING = 0,
\tPROBE_QUEUED,
\tPROBE_OUTSTANDING,
\tPROBE_BENCHED,
\tPROBE_DONE
}\tt_probe_state;
"""
    old_comment = """ * udp_window limits simultaneous UDP probes. udp_send_gap_ms limits how fast
 * probes may be sent to this target even when window capacity remains.
 */
"""
    new_comment = """ * udp_window limits simultaneous UDP probes. udp_send_gap_ms limits how fast
 * probes may be sent to this target even when window capacity remains.
 *
 * udp_retry_limit is the configured hard ceiling. udp_max_successful_retry
 * records the highest retry level that actually produced useful evidence;
 * only the next level beyond that success is allowed to run.
 */
"""
    old_timing = """\tuint64_t\tudp_send_gap_ms;
\tuint64_t\tudp_send_gap_max_ms;

\tsize_t\t\tudp_clean_replies;
\tsize_t\t\tudp_retry_recoveries;
}\tt_nmap_timing;
"""
    new_timing = """\tuint64_t\tudp_send_gap_ms;
\tuint64_t\tudp_send_gap_max_ms;

\tsize_t\t\tudp_clean_replies;
\tsize_t\t\tudp_rate_limit_evidence;

\tsize_t\t\tudp_retry_limit;
\tsize_t\t\tudp_max_successful_retry;
}\tt_nmap_timing;
"""
    old_counts = """\tsize_t\t\t\tdone_count;
\tsize_t\t\t\tqueued_count;
\tsize_t\t\t\toutstanding_count;
\tsize_t\t\t\tudp_queued_count;
\tsize_t\t\t\tudp_outstanding_count;
"""
    new_counts = """\tsize_t\t\t\tdone_count;
\tsize_t\t\t\tqueued_count;
\tsize_t\t\t\toutstanding_count;
\tsize_t\t\t\tbenched_count;
\tsize_t\t\t\tudp_queued_count;
\tsize_t\t\t\tudp_outstanding_count;
"""

    text = replace_once(text, old_state, new_state, RUNTIME_H)
    text = replace_once(text, old_comment, new_comment, RUNTIME_H)
    text = replace_once(text, old_timing, new_timing, RUNTIME_H)
    text = replace_once(text, old_counts, new_counts, RUNTIME_H)
    return text


def patch_internal_h(text):
    old = """void\t\t\tnmap_timing_note_reply_locked(
\t\t\t\t\tt_nmap_config *config,
\t\t\t\t\tconst t_probe *probe,
\t\t\t\t\tuint64_t now_ms);
"""
    new = """size_t\t\t\tnmap_timing_udp_allowed_retries_locked(
\t\t\t\t\tconst t_nmap_config *config);
int\t\t\t\tnmap_timing_note_reply_locked(
\t\t\t\t\tt_nmap_config *config,
\t\t\t\t\tconst t_probe *probe,
\t\t\t\t\tconst t_scan_reason *reason,
\t\t\t\t\tuint64_t now_ms);
"""
    return replace_once(text, old, new, INTERNAL_H)


def patch_common_c(text):
    if "PROBE_BENCHED" in text:
        fail("common.c: BENCHED semble deja applique")

    marker = """/** Remove one QUEUED probe from queue accounting while runtime.lock is held. */
static void\tremove_queued_locked(t_nmap_config *config, const t_probe *probe)
{
\tif (config->runtime.queued_count > 0)
\t\tconfig->runtime.queued_count--;
\tif (nmap_probe_is_udp(probe) && config->runtime.udp_queued_count > 0)
\t\tconfig->runtime.udp_queued_count--;
}

"""
    if text.count(marker) != 1:
        fail("common.c: point d'insertion bench introuvable")
    text = text.replace(marker, marker + BENCH_HELPERS, 1)

    start = text.find(
        "/**\n * @brief Atomically move one logical probe to DONE"
    )
    if start < 0:
        fail("common.c: nmap_mark_probe_done introuvable")

    text = text[:start] + MARK_DONE_SOURCE
    return text


def preflight():
    for path in [RUNTIME_H, INTERNAL_H, COMMON_C, EXPIRE_C, TIMING_C]:
        if not path.exists():
            fail(f"{path}: fichier requis absent")

    if "PROBE_BENCHED" in read(RUNTIME_H):
        fail("patch BENCHED deja present")
    if "udp_rate_limit_evidence" in read(TIMING_C):
        fail("nouvelle politique UDP deja presente")


def main():
    preflight()

    writes = {
        RUNTIME_H: patch_runtime_h(read(RUNTIME_H)),
        INTERNAL_H: patch_internal_h(read(INTERNAL_H)),
        COMMON_C: patch_common_c(read(COMMON_C)),
        EXPIRE_C: EXPIRE_SOURCE,
        TIMING_C: TIMING_SOURCE,
    }

    for path, content in writes.items():
        path.write_text(content, encoding="utf-8")
        print(f"[write] {path}")

    print()
    print("UDP retry policy installed:")
    print("  - DONE probes are never retried")
    print("  - only silent probes consume retry budget")
    print("  - configured retries are a hard ceiling")
    print("  - retry #1 is initially allowed")
    print("  - a successful retry unlocks only the next level")
    print("  - silent probes wait in PROBE_BENCHED")
    print("  - first recovered ICMP enables UDP pacing")
    print("  - second recovered ICMP halves the UDP window")
    print("  - later recovered ICMPs progressively increase the gap")
    print("  - TCP timing policy is unchanged")


if __name__ == "__main__":
    main()