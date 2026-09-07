#include "runtime/runtime_internal.h"

#define NMAP_RTO_MIN_MS 100ULL

#define NMAP_UDP_BACKOFF_RECOVERIES 2
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

/**
 * @brief Initialize target-local adaptive timing policy.
 *
 * The configured TCP timeout is both the conservative initial RTO and the
 * maximum value allowed by this first adaptive implementation.
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

/**
 * @brief Reduce UDP parallelism and increase per-target pacing.
 *
 * The delay never decreases during one target scan. This deliberately keeps
 * the controller monotonic and easy to reason about once rate limiting has
 * been observed.
 */
static void	backoff_udp(t_nmap_timing *timing)
{
	size_t	next_window;
	uint64_t	next_gap;

	next_window = (timing->udp_window + 1) / 2;
	if (next_window < timing->udp_window_min)
		next_window = timing->udp_window_min;
	timing->udp_window = next_window;

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

	timing->udp_clean_replies = 0;
}

/**
 * @brief Slowly restore UDP window capacity after clean first-attempt replies.
 *
 * The pacing delay is intentionally not reduced during the target scan.
 */
static void	note_clean_udp_reply(t_nmap_timing *timing)
{
	timing->udp_clean_replies++;
	if (timing->udp_clean_replies
		< NMAP_UDP_WINDOW_RECOVERY_REPLIES)
		return ;
	if (timing->udp_window < timing->udp_window_max)
		timing->udp_window++;
	timing->udp_retry_recoveries = 0;
	timing->udp_clean_replies = 0;
}

/**
 * @brief Record a UDP response recovered only after retransmission.
 *
 * One recovery may simply be ordinary packet loss. Two nearby recoveries are
 * required before changing pacing/window policy.
 */
static void	note_udp_retry_recovery(t_nmap_timing *timing)
{
	timing->udp_clean_replies = 0;
	timing->udp_retry_recoveries++;
	if (timing->udp_retry_recoveries
		< NMAP_UDP_BACKOFF_RECOVERIES)
		return ;
	backoff_udp(timing);
	timing->udp_retry_recoveries = 0;
}

/**
 * @brief Update target timing from one accepted network response.
 *
 * @note runtime.lock must already be held.
 *
 * Karn rule:
 *   attempts_sent == 1 -> RTT sample is unambiguous.
 *   attempts_sent > 1  -> classify the reply, but never use it as RTT sample.
 */
void	nmap_timing_note_reply_locked(t_nmap_config *config,
		const t_probe *probe, uint64_t now_ms)
{
	t_nmap_timing	*timing;
	uint64_t		sample_ms;

	if (!config || !probe || probe->attempts_sent == 0)
		return ;
	timing = &config->runtime.timing;
	if (probe->attempts_sent == 1
		&& probe->sent_at_ms != 0
		&& now_ms >= probe->sent_at_ms)
	{
		sample_ms = now_ms - probe->sent_at_ms;
		update_rtt(timing, sample_ms);
	}

	if (nmap_probe_is_udp(probe))
	{
		if (probe->attempts_sent > 1)
			note_udp_retry_recovery(timing);
		else
			note_clean_udp_reply(timing);
	}
	else if (probe->attempts_sent > 1)
		backoff_rto(timing);
}
