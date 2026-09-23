#include "runtime/runtime_internal.h"

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
		const t_nmap_target_ctx *ctx)
{
	const t_nmap_timing	*timing;
	size_t				allowed;

	if (!ctx || !nmap_runtime_uses_adaptive_core(ctx))
		return (0);
	timing = &ctx->runtime.timing;
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
void	nmap_timing_init(t_nmap_target_ctx *ctx)
{
	t_nmap_timing	*timing;
	size_t			global_window;
	size_t			udp_window;

	if (!ctx)
		return ;
	timing = &ctx->runtime.timing;
	if (!nmap_runtime_uses_adaptive_core(ctx))
		return ;
	timing->rto_max_ms = (uint64_t)ctx->scan->tcp_timeout_ms;
	if (timing->rto_max_ms == 0)
		timing->rto_max_ms = NMAP_RTO_MIN_MS;
	timing->rto_min_ms = NMAP_RTO_MIN_MS;
	if (timing->rto_max_ms < timing->rto_min_ms)
		timing->rto_min_ms = timing->rto_max_ms;
	timing->rto_ms = timing->rto_max_ms;

	global_window = (size_t)ctx->scan->window_size;
	udp_window = (size_t)ctx->scan->udp_window_size;
	if (global_window == 0)
		global_window = 1;
	if (udp_window == 0)
		udp_window = 1;
	timing->udp_window_min = 1;
	timing->udp_window_max = min_size(global_window, udp_window);
	if (timing->udp_window_max == 0)
		timing->udp_window_max = 1;
	timing->udp_window = timing->udp_window_max;

	if (ctx->scan->udp_send_gap_ms > 0)
		timing->udp_send_gap_ms =
			(uint64_t)ctx->scan->udp_send_gap_ms;
	timing->udp_send_gap_max_ms = NMAP_UDP_BACKOFF_MAX_GAP_MS;
	if (timing->udp_send_gap_ms > timing->udp_send_gap_max_ms)
		timing->udp_send_gap_max_ms = timing->udp_send_gap_ms;

	if (ctx->scan->retries > 0)
		timing->udp_retry_limit = (size_t)ctx->scan->retries;
}

/**
 * @brief Return the timeout applying to one currently outstanding probe.
 *
 * TCP-family scans use the target adaptive RTO after the first valid RTT
 * sample. UDP deliberately keeps the configured UDP timeout.
 */
uint64_t	nmap_timing_probe_timeout_ms(const t_nmap_target_ctx *ctx,
		const t_probe *probe)
{
	if (!ctx || !probe)
		return (0);
	if (!nmap_runtime_uses_adaptive_core(ctx))
	{
		if (nmap_probe_is_udp(probe))
			return ((uint64_t)ctx->scan->udp_timeout_ms);
		return ((uint64_t)ctx->scan->tcp_timeout_ms);
	}
	if (nmap_probe_is_udp(probe))
		return ((uint64_t)ctx->scan->udp_timeout_ms);
	if (!ctx->runtime.timing.rtt_valid)
		return ((uint64_t)ctx->scan->tcp_timeout_ms);
	return (ctx->runtime.timing.rto_ms);
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
		{
			delta = timing->srtt_ms - sample_ms;
		}
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
	{
		next = timing->rto_ms * 2;
	}
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
	{
		next_gap = timing->udp_send_gap_ms * 2;
	}
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
int	nmap_timing_note_reply_locked(t_nmap_target_ctx *ctx,
		const t_probe *probe, const t_scan_reason *reason,
		uint64_t now_ms)
{
	t_nmap_timing	*timing;
	uint64_t		sample_ms;
	int				retry_level_increased;
	int				first_attempt_sample;

	if (!ctx || !probe || !reason || probe->attempts_sent == 0
		|| !nmap_runtime_uses_adaptive_core(ctx))
		return (0);
	timing = &ctx->runtime.timing;
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
