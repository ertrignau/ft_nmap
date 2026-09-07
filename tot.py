#!/usr/bin/env python3

from pathlib import Path
import sys


RUNTIME_H = Path("inc/runtime.h")
INTERNAL_H = Path("srcs/runtime/runtime_internal.h")
COMMON_C = Path("srcs/runtime/common.c")
INIT_C = Path("srcs/runtime/init.c")
EXPIRE_C = Path("srcs/runtime/expire.c")
SCHEDULER_C = Path("srcs/runtime/scheduler.c")
WAIT_C = Path("srcs/runtime/wait.c")
TIMING_C = Path("srcs/runtime/timing.c")
MAKEFILE = Path("Makefile")


TIMING_STRUCT = r'''
/**
 * @brief Adaptive timing state for the current target.
 *
 * RTT estimation and UDP pacing are target-local. The configured scan values
 * remain immutable limits while this structure contains the policy currently
 * selected by the runtime.
 *
 * rto_ms is used for TCP-family retransmission deadlines. UDP keeps its longer
 * configured timeout because silence is a valid open|filtered outcome.
 *
 * udp_window limits simultaneous UDP probes. udp_send_gap_ms limits how fast
 * probes may be sent to this target even when window capacity remains.
 */
typedef struct s_nmap_timing
{
	uint64_t	srtt_ms;
	uint64_t	rttvar_ms;
	uint64_t	rto_ms;
	uint64_t	rto_min_ms;
	uint64_t	rto_max_ms;
	int			rtt_valid;

	size_t		udp_window;
	size_t		udp_window_min;
	size_t		udp_window_max;

	uint64_t	udp_send_gap_ms;
	uint64_t	udp_send_gap_max_ms;

	size_t		udp_clean_replies;
	size_t		udp_retry_recoveries;
}	t_nmap_timing;

'''


TIMING_SOURCE = r'''#include "runtime/runtime_internal.h"

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
'''


TIMING_PROTOTYPES = r'''
/* adaptive target timing */
void			nmap_timing_init(t_nmap_config *config);
uint64_t		nmap_timing_probe_timeout_ms(
					const t_nmap_config *config,
					const t_probe *probe);
void			nmap_timing_note_reply_locked(
					t_nmap_config *config,
					const t_probe *probe,
					uint64_t now_ms);

'''


WAIT_REMAINING = r'''/** Compute remaining milliseconds before one outstanding probe expires. */
static uint64_t	remaining_probe_ms(const t_nmap_config *config,
		const t_probe *probe, uint64_t now_ms)
{
	uint64_t	elapsed;
	uint64_t	timeout_ms;

	timeout_ms = nmap_timing_probe_timeout_ms(config, probe);
	if (timeout_ms == 0 || now_ms <= probe->sent_at_ms)
		return (timeout_ms);
	elapsed = now_ms - probe->sent_at_ms;
	if (elapsed >= timeout_ms)
		return (0);
	return (timeout_ms - elapsed);
}

'''


EXPIRE_CHECK = r'''/** Check whether one OUTSTANDING probe reached its current deadline. */
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
        fail(
            f"{path}: remplacement ambigu pour {old!r} "
            f"(occurrences={count})"
        )
    return text.replace(old, new, 1)


def replace_all_required(text, old, new, path):
    count = text.count(old)
    if count == 0:
        fail(f"{path}: token attendu absent: {old}")
    return text.replace(old, new)


def replace_section(text, start_marker, end_marker, replacement, path):
    start = text.find(start_marker)
    if start < 0:
        fail(f"{path}: debut de section introuvable")
    end = text.find(end_marker, start)
    if end < 0:
        fail(f"{path}: fin de section introuvable")
    return text[:start] + replacement + text[end:]


def patch_runtime_h(text):
    if "typedef struct s_nmap_timing" in text:
        fail("inc/runtime.h: timing adaptatif deja present")

    marker = "/**\n * @brief Runtime state for the current target."
    pos = text.find(marker)
    if pos < 0:
        fail("inc/runtime.h: structure runtime introuvable")

    text = text[:pos] + TIMING_STRUCT + text[pos:]

    old = "\tuint16_t\t\tsource_port_base;\n\tuint64_t\t\tlast_udp_sent_ms;\n"
    new = (
        "\tuint16_t\t\tsource_port_base;\n"
        "\tuint64_t\t\tlast_udp_sent_ms;\n\n"
        "\tt_nmap_timing\ttiming;\n"
    )

    return replace_once(text, old, new, RUNTIME_H)


def patch_internal_h(text):
    if "nmap_timing_init" in text:
        fail("runtime_internal.h: timing prototypes deja presents")

    marker = "\n#endif\n"
    if marker not in text:
        fail("runtime_internal.h: #endif introuvable")

    return text.replace(marker, "\n" + TIMING_PROTOTYPES + "#endif\n", 1)


def patch_makefile(text):
    if "srcs/runtime/timing.c" in text:
        fail("Makefile: timing.c deja present")

    old = "\tsrcs/runtime/common.c \\\n"
    new = (
        "\tsrcs/runtime/common.c \\\n"
        "\tsrcs/runtime/timing.c \\\n"
    )

    return replace_once(text, old, new, MAKEFILE)


def patch_init(text):
    if "nmap_timing_init(config);" in text:
        fail("runtime/init.c: timing deja initialise")

    old = "\tconfig->runtime.lock_initialized = 1;\n"
    new = (
        "\tconfig->runtime.lock_initialized = 1;\n"
        "\tnmap_timing_init(config);\n"
    )

    return replace_once(text, old, new, INIT_C)


def patch_common(text):
    if "nmap_timing_note_reply_locked" in text:
        fail("runtime/common.c: timing reply deja branche")

    old = "\told_state = probe->state;\n"

    new = r'''	if (reason.kind == SCAN_REASON_TCP
		|| reason.kind == SCAN_REASON_UDP_REPLY
		|| reason.kind == SCAN_REASON_ICMP)
		nmap_timing_note_reply_locked(config, probe, nmap_now_ms());
	old_state = probe->state;
'''

    return replace_once(text, old, new, COMMON_C)


def patch_scheduler(text):
    text = replace_all_required(
        text,
        "config->scan.udp_window_size",
        "config->runtime.timing.udp_window",
        SCHEDULER_C,
    )

    text = replace_all_required(
        text,
        "config->scan.udp_send_gap_ms",
        "config->runtime.timing.udp_send_gap_ms",
        SCHEDULER_C,
    )

    return text


def patch_wait(text):
    timeout_start = "/** Return the timeout configured for one probe family. */"
    remaining_start = (
        "/** Compute remaining milliseconds before one outstanding probe expires. */"
    )
    udp_gap_start = "/** Compute remaining delay since the last successful UDP send. */"

    text = replace_section(
        text,
        timeout_start,
        remaining_start,
        "",
        WAIT_C,
    )

    text = replace_section(
        text,
        remaining_start,
        udp_gap_start,
        WAIT_REMAINING,
        WAIT_C,
    )

    text = replace_all_required(
        text,
        "config->scan.udp_send_gap_ms",
        "config->runtime.timing.udp_send_gap_ms",
        WAIT_C,
    )

    return text


def patch_expire(text):
    timeout_start = "/** Return the timeout policy applying to one probe family. */"
    expired_start = "/** Check whether one OUTSTANDING probe reached its current deadline. */"
    remove_start = (
        "/** Remove one probe from outstanding accounting while runtime.lock is held. */"
    )

    text = replace_section(
        text,
        timeout_start,
        expired_start,
        "",
        EXPIRE_C,
    )

    text = replace_section(
        text,
        expired_start,
        remove_start,
        EXPIRE_CHECK,
        EXPIRE_C,
    )

    return text


def preflight():
    required = [
        RUNTIME_H,
        INTERNAL_H,
        COMMON_C,
        INIT_C,
        EXPIRE_C,
        SCHEDULER_C,
        WAIT_C,
        MAKEFILE,
    ]

    for path in required:
        if not path.exists():
            fail(f"{path}: fichier requis absent")

    if TIMING_C.exists():
        fail(
            "srcs/runtime/timing.c existe deja; "
            "aucune modification appliquee"
        )


def main():
    preflight()

    #
    # Charger et transformer TOUT avant la premiere ecriture.
    # Si l'arbre courant ne correspond pas a ce qui est attendu,
    # le script s'arrete sans patch partiel.
    #
    runtime_h = patch_runtime_h(read(RUNTIME_H))
    internal_h = patch_internal_h(read(INTERNAL_H))
    common_c = patch_common(read(COMMON_C))
    init_c = patch_init(read(INIT_C))
    expire_c = patch_expire(read(EXPIRE_C))
    scheduler_c = patch_scheduler(read(SCHEDULER_C))
    wait_c = patch_wait(read(WAIT_C))
    makefile = patch_makefile(read(MAKEFILE))

    writes = {
        RUNTIME_H: runtime_h,
        INTERNAL_H: internal_h,
        COMMON_C: common_c,
        INIT_C: init_c,
        EXPIRE_C: expire_c,
        SCHEDULER_C: scheduler_c,
        WAIT_C: wait_c,
        TIMING_C: TIMING_SOURCE,
        MAKEFILE: makefile,
    }

    for path, content in writes.items():
        path.write_text(content, encoding="utf-8")
        print(f"[write] {path}")

    print()
    print("Adaptive timing installed:")
    print("  TCP: SRTT / RTTVAR / adaptive RTO")
    print("  TCP: Karn rule after retransmission")
    print("  UDP: dynamic outstanding window")
    print("  UDP: adaptive per-target send gap")
    print("  UDP: backoff after repeated retry recoveries")
    print("  UDP: slow window recovery after clean replies")
    print("  Classifier: unchanged")
    print("  Multi-target scheduling: unchanged for now")


if __name__ == "__main__":
    main()