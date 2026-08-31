#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

ROOT = Path.cwd()

REQUIRED = (
    "Makefile",
    "inc/config.h",
    "inc/ft_nmap.h",
    "inc/runtime.h",
    "srcs/main.c",
    "srcs/init/prepare_scan_config.c",
    "srcs/net/pcap.c",
    "srcs/net/route.c",
    "srcs/output/report.c",
    "srcs/parsing/pars_flags.c",
    "srcs/run.c",
    "srcs/runtime/classify.c",
    "srcs/runtime/common.c",
    "srcs/runtime/expire.c",
    "srcs/runtime/recv.c",
    "srcs/runtime/runtime_internal.h",
    "srcs/runtime/scheduler.c",
    "srcs/runtime/wait.c",
    "srcs/runtime/worker.c",
)


def fail(message: str) -> None:
    raise SystemExit(f"tot.py: {message}")


def require_repo() -> None:
    missing = [path for path in REQUIRED if not (ROOT / path).exists()]
    if missing:
        fail("fichiers manquants:\n  - " + "\n  - ".join(missing))


def write(path: str, content: str) -> None:
    target = ROOT / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content.rstrip() + "\n", encoding="utf-8")
    print(f"[write]  {path}")


def replace_exact(path: str, old: str, new: str) -> None:
    target = ROOT / path
    text = target.read_text(encoding="utf-8")
    if old not in text:
        fail(f"motif introuvable dans {path}:\n{old}")
    target.write_text(text.replace(old, new, 1), encoding="utf-8")
    print(f"[patch]  {path}")


def remove(path: str) -> None:
    target = ROOT / path
    if target.exists():
        target.unlink()
        print(f"[remove] {path}")


CONFIG_H = r'''
#ifndef CONFIG_H
# define CONFIG_H

# include "runtime.h"

# include <pcap/pcap.h>
# include <pthread.h>
# include <stddef.h>
# include <stdint.h>
# include <stdio.h>
# include <string.h>

# define NMAP_MAX_PORTS 1024
# define NMAP_MAX_TARGETS 1024
# define NMAP_TARGET_INITIAL_CAPACITY 16
# define NMAP_MAX_THREADS 250
# define NMAP_IFACE_NAME_MAX 64

/**
 * @brief Scan families required by the ft_nmap subject.
 */
typedef enum e_nmap_scan_type
{
	NMAP_SCAN_SYN = 1 << 0,
	NMAP_SCAN_NULL = 1 << 1,
	NMAP_SCAN_FIN = 1 << 2,
	NMAP_SCAN_XMAS = 1 << 3,
	NMAP_SCAN_ACK = 1 << 4,
	NMAP_SCAN_UDP = 1 << 5
}	t_nmap_scan_type;

typedef struct s_nmap_worker	t_nmap_worker;

/**
 * @brief One immutable sender-pool job.
 *
 * @note dispatch_id identifies the exact scheduling generation. A job that is
 *       still waiting in the queue becomes stale as soon as the logical probe
 *       is completed or reserved again with another generation.
 */
typedef struct s_nmap_send_job
{
	t_probe		*probe;
	uint32_t	dispatch_id;
}	t_nmap_send_job;

/**
 * @brief Shared producer/consumer queue for sender threads.
 *
 * Workers only execute an already selected send generation. They never read
 * pcap, classify replies, expire probes, decide retries, or choose scheduling
 * policy. Runtime state changes made by workers are limited to the atomic
 * begin/commit/fail bookkeeping surrounding the actual send syscall.
 */
typedef struct s_nmap_sender_pool
{
	t_nmap_worker	*workers;
	int				worker_count;

	t_nmap_send_job	*queue;
	size_t			queue_capacity;
	size_t			queue_head;
	size_t			queue_tail;
	size_t			queue_count;

	pthread_mutex_t	lock;
	pthread_cond_t	cond;
	int				initialized;
	int				stop_requested;
	int				send_error;
}	t_nmap_sender_pool;

/**
 * @brief Raw options explicitly supplied through the command line.
 *
 * @note The parser records user intent here. Runtime/network policy is
 *       normalized later by nmap_prepare_scan_config().
 */
typedef struct s_nmap_cli
{
	const char	*program_name;
	const char	*target;
	const char	*target_file;
	const char	*ports_arg;
	const char	*scan_arg;

	uint32_t	scan_mask;

	int			help;
	int			no_dns;
	int			version_detection;
	int			os_detection;
	int			open_only;
	int			show_reason;

	int			speedup;
	int			retries;
	int			timeout_ms;

	int			ip_specified;
	int			file_specified;
	int			ports_specified;
	int			scan_specified;
	int			speedup_specified;
	int			retries_specified;
	int			timeout_specified;
}	t_nmap_cli;

/**
 * @brief Owned list of target strings prepared from --ip or --file.
 */
typedef struct s_nmap_targets
{
	char	**items;
	size_t	count;
	size_t	capacity;
}	t_nmap_targets;

/**
 * @brief One currently resolved target.
 *
 * addr is the semantic source of truth. ip is only its cached presentation
 * form for diagnostics, reports and pcap filter construction.
 */
typedef struct s_nmap_target
{
	const char		*name;
	t_nmap_ip_addr	addr;
	char			ip[NMAP_ADDR_TEXT_MAX];
	int				error;
	int				gai_error;
}	t_nmap_target;

/**
 * @brief Route selected by the kernel for the current target.
 *
 * src_addr is the semantic source of truth. src_ip is a cached presentation
 * string. ifindex is also the IPv6 zone when a scoped route is required.
 */
typedef struct s_nmap_route
{
	char			iface[NMAP_IFACE_NAME_MAX];
	unsigned int	ifindex;
	t_nmap_ip_addr	src_addr;
	char			src_ip[NMAP_ADDR_TEXT_MAX];
	int				error;
}	t_nmap_route;

/**
 * @brief Raw send socket for the current target family.
 */
typedef struct s_nmap_socket
{
	int			send_fd;
	sa_family_t	family;
	int			error;
}	t_nmap_socket;

/**
 * @brief Pcap state owned by the main thread.
 */
typedef struct s_nmap_capture
{
	pcap_t	*handle;
	char	errbuf[PCAP_ERRBUF_SIZE];
	int		fd;
	int		datalink;
	int		error;
}	t_nmap_capture;

/**
 * @brief Effective scan configuration consumed by the engine.
 *
 * @note window_size is global. It deliberately does not depend on the number
 *       of sender workers: thread parallelism and network in-flight capacity
 *       are separate concerns.
 */
typedef struct s_nmap_scan
{
	uint16_t	ports[NMAP_MAX_PORTS];
	size_t		port_count;
	uint32_t	scan_mask;

	int			thread_count;
	int			retries;
	int			tcp_timeout_ms;
	int			udp_timeout_ms;

	int			window_size;
	int			udp_window_size;
	int			udp_send_gap_ms;

	int			no_dns;
	int			version_detection;
	int			os_detection;
	int			open_only;
	int			show_reason;
}	t_nmap_scan;

/**
 * @brief Complete process state.
 *
 * Parsing/options and the target list are process-scoped. target/route/socket/
 * capture/runtime/sender_pool are prepared and cleaned for each resolved
 * target.
 */
typedef struct s_nmap_config
{
	t_nmap_cli			cli;
	t_nmap_targets		targets;
	t_nmap_target		target;
	t_nmap_route		route;
	t_nmap_socket		socket;
	t_nmap_capture		capture;
	t_nmap_scan			scan;
	t_nmap_runtime		runtime;
	t_nmap_sender_pool	sender_pool;
}	t_nmap_config;

#endif
'''


RUNTIME_H = r'''
#ifndef NMAP_RUNTIME_H
# define NMAP_RUNTIME_H

# include "ip_addr.h"

# include <pthread.h>
# include <stddef.h>
# include <stdint.h>

/**
 * @brief Runtime lifecycle of one logical probe.
 *
 * PENDING      ready for the scheduler.
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
	PROBE_PENDING = 0,
	PROBE_QUEUED,
	PROBE_OUTSTANDING,
	PROBE_DONE
}	t_probe_state;

/**
 * @brief Final semantic states exposed by the scanner.
 */
typedef enum e_scan_result
{
	SCAN_RESULT_UNKNOWN = 0,
	SCAN_RESULT_OPEN,
	SCAN_RESULT_CLOSED,
	SCAN_RESULT_FILTERED,
	SCAN_RESULT_UNFILTERED,
	SCAN_RESULT_OPEN_FILTERED
}	t_scan_result;

/**
 * @brief Stable reason category retained by a completed logical probe.
 */
typedef enum e_scan_reason_kind
{
	SCAN_REASON_NONE = 0,
	SCAN_REASON_TCP,
	SCAN_REASON_UDP_REPLY,
	SCAN_REASON_ICMP,
	SCAN_REASON_NO_RESPONSE,
	SCAN_REASON_SEND_ERROR
}	t_scan_reason_kind;

/**
 * @brief Structured evidence that produced one final scan result.
 *
 * The runtime keeps protocol facts, not presentation text. report.c is free to
 * turn TCP flags or ICMP family/type/code into a human-readable --reason.
 */
typedef struct s_scan_reason
{
	t_scan_reason_kind	kind;
	sa_family_t			family;
	uint8_t				tcp_flags;
	uint8_t				icmp_type;
	uint8_t				icmp_code;
}	t_scan_reason;

/**
 * @brief One logical scan probe for one destination port and scan type.
 *
 * @note Target/source IP addresses deliberately do not live here. The current
 *       runtime scans one resolved target at a time; family/address ownership
 *       belongs to config.target/config.route instead of being duplicated in
 *       every probe.
 *
 * @note sending_dispatch_id is a transient execution token. A worker sets it
 *       only after validating the current QUEUED generation and immediately
 *       before sendto(). This lets a very fast reply match without lying that
 *       the probe is already OUTSTANDING. OUTSTANDING is committed only after
 *       sendto() succeeds.
 */
typedef struct s_probe
{
	uint16_t		dst_port;
	uint16_t		src_port;
	uint32_t		seq;
	uint32_t		scan_type;
	uint64_t		sent_at_ms;
	uint8_t			attempts_sent;
	uint32_t		dispatch_id;
	uint32_t		sending_dispatch_id;
	t_probe_state	state;
	t_scan_result	result;
	t_scan_reason	reason;
}	t_probe;

/**
 * @brief Parsed network reply kind.
 */
typedef enum e_nmap_reply_type
{
	NMAP_REPLY_NONE = 0,
	NMAP_REPLY_TCP,
	NMAP_REPLY_UDP,
	NMAP_REPLY_ICMP4,
	NMAP_REPLY_ICMP6
}	t_nmap_reply_type;

/**
 * @brief Protocol-independent parsed representation of one captured reply.
 *
 * Direct TCP/UDP replies fill src/dst addresses and ports. ICMP errors also
 * fill the embedded original packet fields, which are required to match the
 * error back to the exact logical probe.
 */
typedef struct s_nmap_reply
{
	t_nmap_reply_type	type;

	t_nmap_ip_addr		src_addr;
	t_nmap_ip_addr		dst_addr;
	uint16_t			src_port;
	uint16_t			dst_port;

	uint8_t				tcp_flags;
	uint32_t			tcp_seq;
	uint32_t			tcp_ack;

	uint8_t				icmp_type;
	uint8_t				icmp_code;

	uint8_t				original_protocol;
	t_nmap_ip_addr		original_src_addr;
	t_nmap_ip_addr		original_dst_addr;
	uint16_t			original_src_port;
	uint16_t			original_dst_port;
	uint32_t			original_tcp_seq;
	int					has_original_tcp_seq;
}	t_nmap_reply;

/**
 * @brief Runtime state for the current target.
 *
 * @note probe_by_src_port gives O(1) candidate lookup. The candidate is still
 *       fully validated before a captured packet is accepted.
 */
typedef struct s_nmap_runtime
{
	t_probe			*probes;
	t_probe			**probe_by_src_port;
	size_t			probe_count;

	size_t			done_count;
	size_t			queued_count;
	size_t			outstanding_count;
	size_t			udp_queued_count;
	size_t			udp_outstanding_count;

	uint16_t		source_port_base;
	uint64_t		last_udp_sent_ms;

	pthread_mutex_t	lock;
	int				lock_initialized;
}	t_nmap_runtime;

#endif
'''


PREPARE_SCAN_CONFIG_C = r'''
/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   prepare_scan_config.c                              :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*                                                                            */
/* ************************************************************************** */

#include "config.h"

#include <stdio.h>

#define NMAP_DEFAULT_RETRIES 1
#define NMAP_MAX_RETRIES 10
#define NMAP_DEFAULT_TCP_TIMEOUT_MS 1000
#define NMAP_DEFAULT_UDP_TIMEOUT_MS 2500
#define NMAP_DEFAULT_WINDOW_SIZE 50
#define NMAP_DEFAULT_UDP_WINDOW 10
#define NMAP_DEFAULT_UDP_SEND_GAP_MS 50

#define NMAP_ALL_SCAN_TYPES \
	(NMAP_SCAN_SYN | NMAP_SCAN_NULL | NMAP_SCAN_FIN \
		| NMAP_SCAN_XMAS | NMAP_SCAN_ACK | NMAP_SCAN_UDP)

/**
 * @brief Fill the mandatory default port range.
 */
static void	set_default_ports(t_nmap_scan *scan)
{
	size_t	i;

	i = 0;
	while (i < NMAP_MAX_PORTS)
	{
		scan->ports[i] = (uint16_t)(i + 1);
		i++;
	}
	scan->port_count = NMAP_MAX_PORTS;
}

/**
 * @brief Normalize the requested port and scan selections.
 */
static int	prepare_selection(t_nmap_config *config)
{
	if (config->scan.port_count == 0)
		set_default_ports(&config->scan);
	if (config->scan.port_count > NMAP_MAX_PORTS)
	{
		fprintf(stderr, "ft_nmap: too many ports\n");
		return (0);
	}
	if (config->cli.scan_specified)
		config->scan.scan_mask = config->cli.scan_mask;
	else
		config->scan.scan_mask = NMAP_ALL_SCAN_TYPES;
	if (config->scan.scan_mask == 0
		|| (config->scan.scan_mask & ~NMAP_ALL_SCAN_TYPES) != 0)
	{
		fprintf(stderr, "ft_nmap: invalid scan mask\n");
		return (0);
	}
	return (1);
}

/**
 * @brief Build the fixed timing/window policy consumed by the runtime.
 *
 * @note Sender-thread count and network window are intentionally independent.
 *       A later RTT/cwnd controller can replace window_size without changing
 *       the worker pool or packet parser.
 */
static int	prepare_timing(t_nmap_config *config)
{
	if (config->cli.speedup < 0 || config->cli.speedup > NMAP_MAX_THREADS)
	{
		fprintf(stderr, "ft_nmap: speedup must be between 0 and %d\n",
			NMAP_MAX_THREADS);
		return (0);
	}
	config->scan.thread_count = config->cli.speedup;
	if (config->cli.retries_specified)
		config->scan.retries = config->cli.retries;
	else
		config->scan.retries = NMAP_DEFAULT_RETRIES;
	if (config->scan.retries < 0 || config->scan.retries > NMAP_MAX_RETRIES)
	{
		fprintf(stderr, "ft_nmap: retries must be between 0 and %d\n",
			NMAP_MAX_RETRIES);
		return (0);
	}
	if (config->cli.timeout_specified)
	{
		if (config->cli.timeout_ms <= 0)
		{
			fprintf(stderr, "ft_nmap: timeout must be positive\n");
			return (0);
		}
		config->scan.tcp_timeout_ms = config->cli.timeout_ms;
		config->scan.udp_timeout_ms = config->cli.timeout_ms;
	}
	else
	{
		config->scan.tcp_timeout_ms = NMAP_DEFAULT_TCP_TIMEOUT_MS;
		config->scan.udp_timeout_ms = NMAP_DEFAULT_UDP_TIMEOUT_MS;
	}
	config->scan.window_size = NMAP_DEFAULT_WINDOW_SIZE;
	config->scan.udp_window_size = NMAP_DEFAULT_UDP_WINDOW;
	if (config->scan.udp_window_size > config->scan.window_size)
		config->scan.udp_window_size = config->scan.window_size;
	config->scan.udp_send_gap_ms = NMAP_DEFAULT_UDP_SEND_GAP_MS;
	return (1);
}

/**
 * @brief Copy optional feature flags into the effective scan configuration.
 */
static void	prepare_features(t_nmap_config *config)
{
	config->scan.no_dns = config->cli.no_dns;
	config->scan.version_detection = config->cli.version_detection;
	config->scan.os_detection = config->cli.os_detection;
	config->scan.open_only = config->cli.open_only;
	config->scan.show_reason = config->cli.show_reason;
}

/**
 * @brief Convert parsed CLI values into the effective scan plan.
 */
int	nmap_prepare_scan_config(t_nmap_config *config, int *exit_status)
{
	if (!config || !prepare_selection(config) || !prepare_timing(config))
	{
		if (exit_status)
			*exit_status = 1;
		return (0);
	}
	prepare_features(config);
	return (1);
}
'''


RUNTIME_INTERNAL_H = r'''
#ifndef NMAP_RUNTIME_INTERNAL_H
# define NMAP_RUNTIME_INTERNAL_H

# include "config.h"

/** Return a monotonic millisecond timestamp used by runtime deadlines. */
uint64_t		nmap_now_ms(void);

/** Return whether one logical probe belongs to the UDP scan family. */
int				nmap_probe_is_udp(const t_probe *probe);

/** Return whether a reply may still legally complete this logical probe. */
int				nmap_probe_can_match(const t_probe *probe);

/**
 * Atomically claim one QUEUED generation immediately before sendto().
 * snapshot may be NULL; when supplied it receives a race-free debug copy.
 */
int				nmap_runtime_begin_send(t_nmap_config *config, t_probe *probe,
					uint32_t dispatch_id, t_probe *snapshot);

/** Commit one successful physical send as OUTSTANDING when still relevant. */
void			nmap_runtime_complete_send(t_nmap_config *config, t_probe *probe,
					uint32_t dispatch_id, uint64_t sent_at_ms);

/**
 * Record one failed physical send.
 * Return 1 when the failure is fatal for the target, 0 when the send belonged
 * to a retry already made irrelevant by a valid late reply.
 */
int				nmap_runtime_fail_send(t_nmap_config *config, t_probe *probe,
					uint32_t dispatch_id);

/** Find and fully validate the logical probe corresponding to one reply. */
t_probe			*nmap_find_matching_probe(t_nmap_config *config,
					t_nmap_reply *reply);

/** Classify one already-matched network reply. */
t_scan_result	nmap_classify_reply(const t_nmap_config *config,
					const t_probe *probe, const t_nmap_reply *reply);

/** Classify final absence of any useful reply after retransmission policy. */
t_scan_result	nmap_classify_no_response(uint32_t scan_type);

/** Atomically finalize one logical probe and update runtime counters. */
void			nmap_mark_probe_done(t_nmap_config *config,
					t_probe *probe, t_scan_result result,
					t_scan_reason reason, const char *debug_reason);

#endif
'''


COMMON_C = r'''
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

/** Check whether one probe belongs to the UDP scan family. */
int	nmap_probe_is_udp(const t_probe *probe)
{
	return (probe && probe->scan_type == NMAP_SCAN_UDP);
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
int	nmap_runtime_begin_send(t_nmap_config *config, t_probe *probe,
		uint32_t dispatch_id, t_probe *snapshot)
{
	int	valid;

	if (!config || !probe)
		return (0);
	pthread_mutex_lock(&config->runtime.lock);
	valid = (probe->state == PROBE_QUEUED
			&& probe->dispatch_id == dispatch_id
			&& probe->sending_dispatch_id == 0);
	if (valid)
	{
		probe->sending_dispatch_id = dispatch_id;
		if (snapshot)
			*snapshot = *probe;
	}
	pthread_mutex_unlock(&config->runtime.lock);
	return (valid);
}

/** Remove one QUEUED probe from queue accounting while runtime.lock is held. */
static void	remove_queued_locked(t_nmap_config *config, const t_probe *probe)
{
	if (config->runtime.queued_count > 0)
		config->runtime.queued_count--;
	if (nmap_probe_is_udp(probe) && config->runtime.udp_queued_count > 0)
		config->runtime.udp_queued_count--;
}

/**
 * @brief Commit a successful sendto() for one claimed generation.
 *
 * If a late reply completed the logical probe while sendto() was executing,
 * the physical send is still accounted as having happened, but DONE is never
 * reopened and queued/outstanding counters are not touched a second time.
 */
void	nmap_runtime_complete_send(t_nmap_config *config, t_probe *probe,
		uint32_t dispatch_id, uint64_t sent_at_ms)
{
	if (!config || !probe)
		return ;
	pthread_mutex_lock(&config->runtime.lock);
	if (probe->dispatch_id != dispatch_id
		|| probe->sending_dispatch_id != dispatch_id)
	{
		pthread_mutex_unlock(&config->runtime.lock);
		return ;
	}
	probe->sending_dispatch_id = 0;
	probe->attempts_sent++;
	if (nmap_probe_is_udp(probe))
		config->runtime.last_udp_sent_ms = sent_at_ms;
	if (probe->state == PROBE_QUEUED)
	{
		remove_queued_locked(config, probe);
		config->runtime.outstanding_count++;
		if (nmap_probe_is_udp(probe))
			config->runtime.udp_outstanding_count++;
		probe->sent_at_ms = sent_at_ms;
		probe->state = PROBE_OUTSTANDING;
	}
	pthread_mutex_unlock(&config->runtime.lock);
}

/**
 * @brief Record a failed sendto() for one claimed generation.
 *
 * A failure on the first physical attempt is always fatal. A retry can become
 * obsolete while sendto() is executing if a late reply from an earlier attempt
 * completes the probe; in that case the already-valid network result wins and
 * the obsolete retry failure does not poison the whole target.
 */
int	nmap_runtime_fail_send(t_nmap_config *config, t_probe *probe,
		uint32_t dispatch_id)
{
	t_scan_reason	reason;
	int				fatal;
	int				marked_done;

	if (!config || !probe)
		return (0);
	fatal = 0;
	marked_done = 0;
	pthread_mutex_lock(&config->runtime.lock);
	if (probe->dispatch_id == dispatch_id
		&& probe->sending_dispatch_id == dispatch_id)
	{
		probe->sending_dispatch_id = 0;
		if (probe->state == PROBE_DONE)
			fatal = (probe->attempts_sent == 0);
		else if (probe->state == PROBE_QUEUED)
		{
			remove_queued_locked(config, probe);
			reason = (t_scan_reason){0};
			reason.kind = SCAN_REASON_SEND_ERROR;
			probe->state = PROBE_DONE;
			probe->result = SCAN_RESULT_UNKNOWN;
			probe->reason = reason;
			config->runtime.done_count++;
			fatal = 1;
			marked_done = 1;
		}
	}
	pthread_mutex_unlock(&config->runtime.lock);
	if (marked_done)
		DEBUG_PROBE_RESULT(probe, "send failure");
	return (fatal);
}

/**
 * @brief Atomically move one logical probe to DONE and maintain counters.
 *
 * @note The operation is idempotent for late duplicate replies. If a worker
 *       already claimed the current QUEUED generation, the physical send may
 *       still finish, but its later commit cannot reopen this DONE probe.
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
		remove_queued_locked(config, probe);
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
'''


SCHEDULER_C = r'''
#include "config.h"
#include "debug/debug.h"
#include "packet/packet.h"
#include "runtime/runtime_internal.h"
#include "runtime/worker.h"

/** Return total queued + outstanding logical probes while runtime.lock is held. */
static size_t	active_count_locked(const t_nmap_config *config)
{
	return (config->runtime.queued_count
		+ config->runtime.outstanding_count);
}

/** Return active UDP probes while runtime.lock is held. */
static size_t	udp_active_count_locked(const t_nmap_config *config)
{
	return (config->runtime.udp_queued_count
		+ config->runtime.udp_outstanding_count);
}

/** Check whether the configured gap since the last real UDP send elapsed. */
static int	udp_gap_allows_locked(const t_nmap_config *config,
		uint64_t now_ms)
{
	uint64_t	elapsed;

	if (config->scan.udp_send_gap_ms <= 0
		|| config->runtime.last_udp_sent_ms == 0)
		return (1);
	if (now_ms <= config->runtime.last_udp_sent_ms)
		return (0);
	elapsed = now_ms - config->runtime.last_udp_sent_ms;
	return (elapsed >= (uint64_t)config->scan.udp_send_gap_ms);
}

/**
 * @brief Check whether one PENDING probe can consume scheduler capacity now.
 *
 * Only one UDP job is allowed to remain QUEUED at a time. This makes the UDP
 * pacing timestamp refer to actual successful sends rather than to reservations
 * that may sit in a worker queue for an arbitrary duration.
 */
static int	probe_can_be_reserved_locked(const t_nmap_config *config,
		const t_probe *probe, uint64_t now_ms)
{
	if (probe->state != PROBE_PENDING)
		return (0);
	if (active_count_locked(config) >= (size_t)config->scan.window_size)
		return (0);
	if (!nmap_probe_is_udp(probe))
		return (1);
	if (udp_active_count_locked(config)
		>= (size_t)config->scan.udp_window_size)
		return (0);
	if (config->runtime.udp_queued_count > 0)
		return (0);
	return (udp_gap_allows_locked(config, now_ms));
}

/** Reserve one exact send generation in QUEUED state. */
static uint32_t	reserve_probe_locked(t_nmap_config *config, t_probe *probe)
{
	probe->state = PROBE_QUEUED;
	probe->dispatch_id++;
	probe->sending_dispatch_id = 0;
	config->runtime.queued_count++;
	if (nmap_probe_is_udp(probe))
		config->runtime.udp_queued_count++;
	return (probe->dispatch_id);
}

/** Undo a reservation that never reached a sender. */
static void	revert_reservation(t_nmap_config *config,
		t_probe *probe, uint32_t dispatch_id)
{
	pthread_mutex_lock(&config->runtime.lock);
	if (probe->state == PROBE_QUEUED
		&& probe->dispatch_id == dispatch_id
		&& probe->sending_dispatch_id == 0)
	{
		probe->state = PROBE_PENDING;
		if (config->runtime.queued_count > 0)
			config->runtime.queued_count--;
		if (nmap_probe_is_udp(probe)
			&& config->runtime.udp_queued_count > 0)
			config->runtime.udp_queued_count--;
	}
	pthread_mutex_unlock(&config->runtime.lock);
}

/** Reserve one PENDING probe and return its new generation. */
static int	reserve_probe(t_nmap_config *config, t_probe *probe,
		uint64_t now_ms, uint32_t *dispatch_id)
{
	int	reserved;

	pthread_mutex_lock(&config->runtime.lock);
	reserved = probe_can_be_reserved_locked(config, probe, now_ms);
	if (reserved)
		*dispatch_id = reserve_probe_locked(config, probe);
	pthread_mutex_unlock(&config->runtime.lock);
	return (reserved);
}

/** Send one already-reserved generation synchronously from the main thread. */
static int	send_reserved_inline(t_nmap_config *config, t_probe *probe,
		uint32_t dispatch_id, int *exit_status)
{
	t_probe		snapshot;
	uint64_t	sent_at_ms;

	if (!nmap_runtime_begin_send(config, probe, dispatch_id, &snapshot))
		return (1);
	DEBUG_PROBE_SEND(&snapshot);
	if (!nmap_send_probe(config, probe))
	{
		(void)nmap_runtime_fail_send(config, probe, dispatch_id);
		if (exit_status)
			*exit_status = 1;
		return (0);
	}
	sent_at_ms = nmap_now_ms();
	nmap_runtime_complete_send(config, probe, dispatch_id, sent_at_ms);
	return (1);
}

/** Reserve and enqueue one probe for sender-thread execution. */
static int	queue_threaded(t_nmap_config *config, t_probe *probe,
		uint64_t now_ms, int *exit_status)
{
	uint32_t	dispatch_id;

	if (!reserve_probe(config, probe, now_ms, &dispatch_id))
		return (1);
	if (!nmap_dispatch_probe_to_sender(config, probe, dispatch_id))
	{
		revert_reservation(config, probe, dispatch_id);
		if (nmap_sender_pool_has_error(config))
		{
			if (exit_status)
				*exit_status = 1;
			return (0);
		}
	}
	return (1);
}

/** Reserve and execute one probe directly from the main thread. */
static int	send_inline(t_nmap_config *config, t_probe *probe,
		uint64_t now_ms, int *exit_status)
{
	uint32_t	dispatch_id;

	if (!reserve_probe(config, probe, now_ms, &dispatch_id))
		return (1);
	return (send_reserved_inline(config, probe, dispatch_id, exit_status));
}

/** Check whether the global send window is currently full. */
static int	global_window_full(t_nmap_config *config)
{
	int	full;

	pthread_mutex_lock(&config->runtime.lock);
	full = (active_count_locked(config)
			>= (size_t)config->scan.window_size);
	pthread_mutex_unlock(&config->runtime.lock);
	return (full);
}

/**
 * @brief Schedule every currently eligible PENDING probe while capacity allows.
 *
 * This function owns send order and window policy. Workers can only execute a
 * generation already reserved here and cannot bypass global/UDP limits.
 */
int	nmap_runtime_schedule_ready(t_nmap_config *config, int *exit_status)
{
	size_t		i;
	uint64_t	now_ms;
	int			threaded;

	if (!config || config->scan.window_size <= 0)
	{
		if (exit_status)
			*exit_status = 1;
		return (0);
	}
	if (nmap_sender_pool_has_error(config))
	{
		if (exit_status)
			*exit_status = 1;
		return (0);
	}
	threaded = (config->sender_pool.worker_count > 0);
	i = 0;
	while (i < config->runtime.probe_count)
	{
		if (global_window_full(config))
			break ;
		now_ms = nmap_now_ms();
		if (threaded)
		{
			if (!queue_threaded(config, &config->runtime.probes[i],
					now_ms, exit_status))
				return (0);
		}
		else if (!send_inline(config, &config->runtime.probes[i],
				now_ms, exit_status))
			return (0);
		i++;
	}
	return (1);
}
'''


WORKER_C = r'''
#include "runtime/worker.h"
#include "debug/debug.h"
#include "packet/packet.h"
#include "runtime/runtime_internal.h"

#include <stdlib.h>
#include <string.h>

/**
 * @brief Pop one job from the shared sender queue, blocking until work/stop.
 */
static int	pool_pop_job(t_nmap_sender_pool *pool, t_nmap_send_job *job)
{
	pthread_mutex_lock(&pool->lock);
	while (pool->queue_count == 0 && !pool->stop_requested)
		pthread_cond_wait(&pool->cond, &pool->lock);
	if (pool->stop_requested)
	{
		pthread_mutex_unlock(&pool->lock);
		return (0);
	}
	*job = pool->queue[pool->queue_head];
	pool->queue_head = (pool->queue_head + 1) % pool->queue_capacity;
	pool->queue_count--;
	pthread_mutex_unlock(&pool->lock);
	return (1);
}

/** Record a fatal sender error visible to the main event loop. */
static void	set_send_error(t_nmap_sender_pool *pool)
{
	pthread_mutex_lock(&pool->lock);
	pool->send_error = 1;
	pthread_mutex_unlock(&pool->lock);
}

/**
 * @brief Execute one already-reserved generation.
 *
 * The worker does not decide any lifecycle policy. begin_send() only validates
 * that this exact QUEUED generation is still current and creates a short-lived
 * execution token. OUTSTANDING is committed only after sendto() succeeds.
 *
 * Once begin_send() succeeds, the physical send is considered committed. A
 * late reply can still complete the logical probe while sendto() is running;
 * complete_send() then observes DONE and never reopens it.
 */
static void	execute_job(t_nmap_worker *worker, const t_nmap_send_job *job)
{
	t_probe		snapshot;
	uint64_t	sent_at_ms;
	int			fatal;

	if (!nmap_runtime_begin_send(worker->config, job->probe,
			job->dispatch_id, &snapshot))
		return ;
	DEBUG_PROBE_SEND(&snapshot);
	if (!nmap_send_probe(worker->config, job->probe))
	{
		fatal = nmap_runtime_fail_send(worker->config,
				job->probe, job->dispatch_id);
		if (fatal)
			set_send_error(&worker->config->sender_pool);
		return ;
	}
	sent_at_ms = nmap_now_ms();
	nmap_runtime_complete_send(worker->config, job->probe,
		job->dispatch_id, sent_at_ms);
}

/**
 * @brief Sender worker entry point.
 *
 * No pcap, matching, classification, expiration, retry or scheduling policy
 * belongs in this loop.
 */
static void	*worker_main(void *arg)
{
	t_nmap_worker	*worker;
	t_nmap_send_job	job;

	worker = (t_nmap_worker *)arg;
	while (pool_pop_job(&worker->config->sender_pool, &job))
		execute_job(worker, &job);
	return (NULL);
}

/** Initialize and start one sender worker. */
static int	init_worker(t_nmap_config *config, t_nmap_worker *worker,
		int id)
{
	memset(worker, 0, sizeof(*worker));
	worker->config = config;
	worker->id = id;
	if (pthread_create(&worker->thread, NULL, worker_main, worker) != 0)
		return (0);
	worker->started = 1;
	return (1);
}

/**
 * @brief Initialize the shared sender queue and requested worker threads.
 *
 * @note speedup=0 intentionally keeps an inline main-thread sender and does
 *       not initialize pool synchronization primitives.
 */
int	nmap_prepare_sender_pool(t_nmap_config *config, int *exit_status)
{
	int	i;

	if (!config)
		goto fail;
	memset(&config->sender_pool, 0, sizeof(config->sender_pool));
	config->sender_pool.worker_count = config->scan.thread_count;
	if (config->sender_pool.worker_count <= 0)
	{
		config->sender_pool.worker_count = 0;
		return (1);
	}
	if (pthread_mutex_init(&config->sender_pool.lock, NULL) != 0)
		goto fail;
	if (pthread_cond_init(&config->sender_pool.cond, NULL) != 0)
	{
		pthread_mutex_destroy(&config->sender_pool.lock);
		goto fail;
	}
	config->sender_pool.initialized = 1;
	config->sender_pool.queue_capacity = config->runtime.probe_count;
	if (config->sender_pool.queue_capacity == 0)
		goto fail_initialized;
	config->sender_pool.queue = calloc(config->sender_pool.queue_capacity,
			sizeof(*config->sender_pool.queue));
	config->sender_pool.workers = calloc(config->sender_pool.worker_count,
			sizeof(*config->sender_pool.workers));
	if (!config->sender_pool.queue || !config->sender_pool.workers)
		goto fail_initialized;
	i = 0;
	while (i < config->sender_pool.worker_count)
	{
		if (!init_worker(config, &config->sender_pool.workers[i], i))
			goto fail_initialized;
		i++;
	}
	return (1);
fail_initialized:
	if (exit_status)
		*exit_status = 1;
	nmap_stop_sender_pool(config);
	return (0);
fail:
	if (exit_status)
		*exit_status = 1;
	return (0);
}

/**
 * @brief Stop and join every sender worker, then release pool resources.
 */
void	nmap_stop_sender_pool(t_nmap_config *config)
{
	int	i;

	if (!config || !config->sender_pool.initialized)
		return ;
	pthread_mutex_lock(&config->sender_pool.lock);
	config->sender_pool.stop_requested = 1;
	pthread_cond_broadcast(&config->sender_pool.cond);
	pthread_mutex_unlock(&config->sender_pool.lock);
	i = 0;
	while (i < config->sender_pool.worker_count)
	{
		if (config->sender_pool.workers
			&& config->sender_pool.workers[i].started)
			pthread_join(config->sender_pool.workers[i].thread, NULL);
		i++;
	}
	free(config->sender_pool.workers);
	free(config->sender_pool.queue);
	pthread_cond_destroy(&config->sender_pool.cond);
	pthread_mutex_destroy(&config->sender_pool.lock);
	memset(&config->sender_pool, 0, sizeof(config->sender_pool));
}

/** Return whether any relevant sender job reported a fatal send failure. */
int	nmap_sender_pool_has_error(t_nmap_config *config)
{
	int	error;

	if (!config || !config->sender_pool.initialized)
		return (0);
	pthread_mutex_lock(&config->sender_pool.lock);
	error = config->sender_pool.send_error;
	pthread_mutex_unlock(&config->sender_pool.lock);
	return (error != 0);
}

/**
 * @brief Push one already-reserved probe generation into the shared queue.
 */
int	nmap_dispatch_probe_to_sender(t_nmap_config *config, t_probe *probe,
		uint32_t dispatch_id)
{
	t_nmap_sender_pool	*pool;

	if (!config || !probe || !config->sender_pool.initialized)
		return (0);
	pool = &config->sender_pool;
	pthread_mutex_lock(&pool->lock);
	if (pool->stop_requested || pool->send_error
		|| pool->queue_count >= pool->queue_capacity)
	{
		pthread_mutex_unlock(&pool->lock);
		return (0);
	}
	pool->queue[pool->queue_tail].probe = probe;
	pool->queue[pool->queue_tail].dispatch_id = dispatch_id;
	pool->queue_tail = (pool->queue_tail + 1) % pool->queue_capacity;
	pool->queue_count++;
	pthread_cond_signal(&pool->cond);
	pthread_mutex_unlock(&pool->lock);
	return (1);
}
'''


WAIT_C = r'''
#include "config.h"
#include "debug/debug.h"
#include "runtime/runtime_internal.h"

#include <errno.h>
#include <stdio.h>
#include <sys/select.h>
#include <sys/time.h>
#include <time.h>

/** Return current monotonic time in microseconds for profiling/select. */
static uint64_t	now_us(void)
{
	struct timespec	ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return (0);
	return ((uint64_t)ts.tv_sec * 1000000ULL
		+ (uint64_t)ts.tv_nsec / 1000ULL);
}

/** Return the timeout configured for one probe family. */
static int	probe_timeout_ms(const t_nmap_config *config,
		const t_probe *probe)
{
	if (nmap_probe_is_udp(probe))
		return (config->scan.udp_timeout_ms);
	return (config->scan.tcp_timeout_ms);
}

/** Compute remaining milliseconds before one outstanding probe expires. */
static uint64_t	remaining_probe_ms(const t_nmap_config *config,
		const t_probe *probe, uint64_t now_ms)
{
	uint64_t	elapsed;
	int			timeout_ms;

	timeout_ms = probe_timeout_ms(config, probe);
	if (timeout_ms <= 0 || now_ms <= probe->sent_at_ms)
		return ((timeout_ms <= 0) ? 0 : (uint64_t)timeout_ms);
	elapsed = now_ms - probe->sent_at_ms;
	if (elapsed >= (uint64_t)timeout_ms)
		return (0);
	return ((uint64_t)timeout_ms - elapsed);
}

/** Compute remaining delay since the last successful UDP send. */
static uint64_t	remaining_udp_gap_ms(const t_nmap_config *config,
		uint64_t now_ms)
{
	uint64_t	elapsed;

	if (config->scan.udp_send_gap_ms <= 0
		|| config->runtime.last_udp_sent_ms == 0)
		return (0);
	if (now_ms <= config->runtime.last_udp_sent_ms)
		return ((uint64_t)config->scan.udp_send_gap_ms);
	elapsed = now_ms - config->runtime.last_udp_sent_ms;
	if (elapsed >= (uint64_t)config->scan.udp_send_gap_ms)
		return (0);
	return ((uint64_t)config->scan.udp_send_gap_ms - elapsed);
}

/** Register one candidate duration and preserve the nearest deadline. */
static void	update_wait(uint64_t *wait_ms, int *found, uint64_t candidate)
{
	if (!*found || candidate < *wait_ms)
		*wait_ms = candidate;
	*found = 1;
}

/** Return whether a PENDING UDP probe exists while runtime.lock is held. */
static int	has_pending_udp_locked(const t_nmap_config *config)
{
	size_t	i;

	i = 0;
	while (i < config->runtime.probe_count)
	{
		if (config->runtime.probes[i].state == PROBE_PENDING
			&& nmap_probe_is_udp(&config->runtime.probes[i]))
			return (1);
		i++;
	}
	return (0);
}

/**
 * @brief Compute how long select() may sleep before the next useful event.
 *
 * Candidates are outstanding-probe deadlines, queued-worker progress and the
 * real UDP send pacing deadline. Pcap readability may wake select earlier.
 */
static int	get_next_wait_ms(t_nmap_config *config,
		uint64_t *wait_ms, uint64_t *sample_us)
{
	size_t		i;
	uint64_t	now_ms;
	uint64_t	remaining;
	int			found;

	*sample_us = now_us();
	now_ms = *sample_us / 1000ULL;
	found = 0;
	pthread_mutex_lock(&config->runtime.lock);
	if (config->runtime.queued_count > 0)
		update_wait(wait_ms, &found, 1);
	i = 0;
	while (i < config->runtime.probe_count)
	{
		if (config->runtime.probes[i].state == PROBE_OUTSTANDING)
		{
			remaining = remaining_probe_ms(config,
					&config->runtime.probes[i], now_ms);
			update_wait(wait_ms, &found, remaining);
		}
		i++;
	}
	if (has_pending_udp_locked(config))
	{
		remaining = remaining_udp_gap_ms(config, now_ms);
		if (remaining > 0)
			update_wait(wait_ms, &found, remaining);
	}
	pthread_mutex_unlock(&config->runtime.lock);
	return (found);
}

/** Convert a millisecond duration to select() timeval form. */
static void	set_timeval(uint64_t ms, struct timeval *timeout)
{
	timeout->tv_sec = ms / 1000ULL;
	timeout->tv_usec = (ms % 1000ULL) * 1000ULL;
}

/**
 * @brief Block until pcap activity or the nearest runtime deadline.
 */
int	nmap_runtime_wait(t_nmap_config *config, int *exit_status)
{
	fd_set			readfds;
	struct timeval	timeout;
	uint64_t		wait_ms;
	uint64_t		before_us;
	uint64_t		after_us;
	int				ret;

	if (!config || config->capture.fd < 0)
	{
		if (exit_status)
			*exit_status = 1;
		return (0);
	}
	if (!get_next_wait_ms(config, &wait_ms, &before_us))
		return (1);
	FD_ZERO(&readfds);
	FD_SET(config->capture.fd, &readfds);
	set_timeval(wait_ms, &timeout);
	ret = select(config->capture.fd + 1,
			&readfds, NULL, NULL, &timeout);
	after_us = now_us();
	PROF_ADD_VALUE(NMAP_PROF_SELECT_REQUESTED, wait_ms * 1000ULL);
	PROF_ADD_VALUE(NMAP_PROF_SELECT_WAIT, after_us - before_us);
	if (ret < 0)
	{
		if (errno == EINTR)
			return (1);
		perror("ft_nmap: select");
		if (exit_status)
			*exit_status = 1;
		return (0);
	}
	return (1);
}
'''


EXPIRE_C = r'''
#include "config.h"
#include "debug/debug.h"
#include "runtime/runtime_internal.h"

/** Return the timeout policy applying to one probe family. */
static int	probe_timeout_ms(const t_nmap_config *config,
		const t_probe *probe)
{
	if (nmap_probe_is_udp(probe))
		return (config->scan.udp_timeout_ms);
	return (config->scan.tcp_timeout_ms);
}

/** Check whether one OUTSTANDING probe reached its current deadline. */
static int	probe_expired(const t_nmap_config *config,
		const t_probe *probe, uint64_t now_ms)
{
	int			timeout_ms;
	uint64_t	elapsed;

	if (probe->state != PROBE_OUTSTANDING)
		return (0);
	timeout_ms = probe_timeout_ms(config, probe);
	if (timeout_ms <= 0)
		return (1);
	if (now_ms <= probe->sent_at_ms)
		return (0);
	elapsed = now_ms - probe->sent_at_ms;
	return (elapsed >= (uint64_t)timeout_ms);
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
'''


CLASSIFY_C = r'''
#include "runtime/runtime_internal.h"
#include "net/address.h"
#include "packet/wire.h"

/**
 * @brief Return whether an ICMPv4 Destination Unreachable code participates in
 *        the scan decision trees.
 */
static int	icmp4_unreachable_code_is_known(uint8_t code)
{
	return (code == 0 || code == 1 || code == 2 || code == 3
		|| code == 9 || code == 10 || code == 13);
}

/**
 * @brief Classify a matched direct TCP response according to scan type.
 */
static t_scan_result	classify_tcp_packet(const t_probe *probe,
		const t_nmap_reply *reply)
{
	uint8_t	flags;

	flags = reply->tcp_flags;
	if (probe->scan_type == NMAP_SCAN_SYN)
	{
		if ((flags & NMAP_TCP_SYN) && (flags & NMAP_TCP_ACK))
			return (SCAN_RESULT_OPEN);
		if (flags & NMAP_TCP_RST)
			return (SCAN_RESULT_CLOSED);
		/* Keep split-handshake support explicit rather than accidental. */
		if (flags & NMAP_TCP_SYN)
			return (SCAN_RESULT_OPEN);
	}
	else if (probe->scan_type == NMAP_SCAN_ACK)
	{
		if (flags & NMAP_TCP_RST)
			return (SCAN_RESULT_UNFILTERED);
	}
	else if (probe->scan_type == NMAP_SCAN_NULL
		|| probe->scan_type == NMAP_SCAN_FIN
		|| probe->scan_type == NMAP_SCAN_XMAS)
	{
		if (flags & NMAP_TCP_RST)
			return (SCAN_RESULT_CLOSED);
	}
	return (SCAN_RESULT_UNKNOWN);
}

/**
 * @brief Classify one matched ICMPv4 error.
 */
static t_scan_result	classify_icmp4(const t_nmap_config *config,
		const t_probe *probe, const t_nmap_reply *reply)
{
	if (reply->icmp_type == 11)
		return (SCAN_RESULT_FILTERED);
	if (reply->icmp_type != 3
		|| !icmp4_unreachable_code_is_known(reply->icmp_code))
		return (SCAN_RESULT_UNKNOWN);
	if (probe->scan_type == NMAP_SCAN_UDP && reply->icmp_code == 3)
	{
		if (nmap_ip_equal(&reply->src_addr, &config->target.addr))
			return (SCAN_RESULT_CLOSED);
		return (SCAN_RESULT_FILTERED);
	}
	return (SCAN_RESULT_FILTERED);
}

/**
 * @brief Classify one matched ICMPv6 error.
 *
 * Destination Unreachable type 1 codes 0..6 are filtering/unreachable
 * evidence, except UDP port-unreachable 1/4 from the target itself -> CLOSED.
 * Time Exceeded type 3 is filtering/path evidence for the current scan.
 * Packet Too Big and Parameter Problem are not port-state evidence here and
 * deliberately remain UNKNOWN instead of inventing an OPEN result.
 */
static t_scan_result	classify_icmp6(const t_nmap_config *config,
		const t_probe *probe, const t_nmap_reply *reply)
{
	if (reply->icmp_type == 1 && reply->icmp_code <= 6)
	{
		if (probe->scan_type == NMAP_SCAN_UDP && reply->icmp_code == 4
			&& nmap_ip_equal(&reply->src_addr, &config->target.addr))
			return (SCAN_RESULT_CLOSED);
		return (SCAN_RESULT_FILTERED);
	}
	if (reply->icmp_type == 3 && reply->icmp_code <= 1)
		return (SCAN_RESULT_FILTERED);
	return (SCAN_RESULT_UNKNOWN);
}

/**
 * @brief Apply the per-scan response decision tree to one already-matched reply.
 */
t_scan_result	nmap_classify_reply(const t_nmap_config *config,
		const t_probe *probe, const t_nmap_reply *reply)
{
	if (!config || !probe || !reply)
		return (SCAN_RESULT_UNKNOWN);
	if (reply->type == NMAP_REPLY_TCP && probe->scan_type != NMAP_SCAN_UDP)
		return (classify_tcp_packet(probe, reply));
	if (reply->type == NMAP_REPLY_UDP && probe->scan_type == NMAP_SCAN_UDP)
		return (SCAN_RESULT_OPEN);
	if (reply->type == NMAP_REPLY_ICMP4)
		return (classify_icmp4(config, probe, reply));
	if (reply->type == NMAP_REPLY_ICMP6)
		return (classify_icmp6(config, probe, reply));
	return (SCAN_RESULT_UNKNOWN);
}

/**
 * @brief Classify final absence of a matching response after retry policy.
 */
t_scan_result	nmap_classify_no_response(uint32_t scan_type)
{
	if (scan_type == NMAP_SCAN_SYN || scan_type == NMAP_SCAN_ACK)
		return (SCAN_RESULT_FILTERED);
	if (scan_type == NMAP_SCAN_NULL || scan_type == NMAP_SCAN_FIN
		|| scan_type == NMAP_SCAN_XMAS || scan_type == NMAP_SCAN_UDP)
		return (SCAN_RESULT_OPEN_FILTERED);
	return (SCAN_RESULT_UNKNOWN);
}
'''


RECV_C = r'''
#include "config.h"
#include "debug/debug.h"
#include "packet/packet.h"
#include "runtime/runtime_internal.h"

#include <pcap/pcap.h>
#include <stdio.h>

/** Return structured report evidence represented by one matched reply. */
static t_scan_reason	reply_reason(const t_nmap_reply *reply)
{
	t_scan_reason	reason;

	reason = (t_scan_reason){0};
	if (!reply)
		return (reason);
	if (reply->type == NMAP_REPLY_UDP)
		reason.kind = SCAN_REASON_UDP_REPLY;
	else if (reply->type == NMAP_REPLY_TCP)
	{
		reason.kind = SCAN_REASON_TCP;
		reason.tcp_flags = reply->tcp_flags;
	}
	else if (reply->type == NMAP_REPLY_ICMP4
		|| reply->type == NMAP_REPLY_ICMP6)
	{
		reason.kind = SCAN_REASON_ICMP;
		if (reply->type == NMAP_REPLY_ICMP4)
			reason.family = AF_INET;
		else
			reason.family = AF_INET6;
		reason.icmp_type = reply->icmp_type;
		reason.icmp_code = reply->icmp_code;
	}
	return (reason);
}

/**
 * @brief Parse, match and classify one captured frame.
 *
 * @return 1 when the frame finalized a probe, 0 when it was safely ignored.
 */
static int	handle_captured_packet(t_nmap_config *config,
		const unsigned char *packet, size_t len)
{
	t_nmap_reply	reply;
	t_probe			*probe;
	t_scan_result	result;
	uint64_t		prof_start;

	DEBUG_RECV_PACKET(packet, len);
	prof_start = PROF_START();
	if (!nmap_parse_pcap_packet(config, packet, len, &reply))
	{
		PROF_ADD(NMAP_PROF_PACKET_PARSE_TOTAL, prof_start);
		PROF_COUNT(NMAP_PROF_PACKET_IGNORED);
		return (0);
	}
	PROF_ADD(NMAP_PROF_PACKET_PARSE_TOTAL, prof_start);
	PROF_COUNT(NMAP_PROF_PACKET_PARSED);
	prof_start = PROF_START();
	probe = nmap_find_matching_probe(config, &reply);
	PROF_ADD(NMAP_PROF_MATCH_PROBE, prof_start);
	if (!probe)
	{
		PROF_COUNT(NMAP_PROF_PACKET_IGNORED);
		return (0);
	}
	prof_start = PROF_START();
	result = nmap_classify_reply(config, probe, &reply);
	PROF_ADD(NMAP_PROF_CLASSIFY, prof_start);
	if (result == SCAN_RESULT_UNKNOWN)
	{
		PROF_COUNT(NMAP_PROF_PACKET_IGNORED);
		return (0);
	}
	PROF_COUNT(NMAP_PROF_PACKET_MATCHED);
	nmap_mark_probe_done(config, probe, result, reply_reason(&reply), "reply");
	return (1);
}

/** @brief Drain every pcap frame currently available without blocking. */
int	nmap_runtime_drain_replies(t_nmap_config *config, int *exit_status)
{
	struct pcap_pkthdr	*header;
	const unsigned char	*packet;
	int					ret;
	uint64_t			prof_start;

	if (!config || !config->capture.handle)
	{
		if (exit_status)
			*exit_status = 1;
		return (0);
	}
	while (1)
	{
		prof_start = PROF_START();
		ret = pcap_next_ex(config->capture.handle, &header, &packet);
		PROF_ADD(NMAP_PROF_PCAP_NEXT_EX, prof_start);
		if (ret == 1)
		{
			PROF_COUNT(NMAP_PROF_PACKET_SEEN);
			handle_captured_packet(config, packet, header->caplen);
		}
		else if (ret == 0 || ret == PCAP_ERROR_BREAK)
			return (1);
		else
		{
			fprintf(stderr, "ft_nmap: pcap_next_ex: %s\n",
				pcap_geterr(config->capture.handle));
			if (exit_status)
				*exit_status = 1;
			return (0);
		}
	}
}
'''


REPORT_C = r'''
#include "config.h"
#include "packet/wire.h"

#include <stdio.h>

/** Return the display name for one concrete scan type. */
static const char	*scan_type_name(uint32_t scan_type)
{
	if (scan_type == NMAP_SCAN_SYN)
		return ("SYN");
	if (scan_type == NMAP_SCAN_NULL)
		return ("NULL");
	if (scan_type == NMAP_SCAN_FIN)
		return ("FIN");
	if (scan_type == NMAP_SCAN_XMAS)
		return ("XMAS");
	if (scan_type == NMAP_SCAN_ACK)
		return ("ACK");
	if (scan_type == NMAP_SCAN_UDP)
		return ("UDP");
	return ("UNKNOWN");
}

/** Return the display name for one final scan result. */
static const char	*scan_result_name(t_scan_result result)
{
	if (result == SCAN_RESULT_OPEN)
		return ("open");
	if (result == SCAN_RESULT_CLOSED)
		return ("closed");
	if (result == SCAN_RESULT_FILTERED)
		return ("filtered");
	if (result == SCAN_RESULT_UNFILTERED)
		return ("unfiltered");
	if (result == SCAN_RESULT_OPEN_FILTERED)
		return ("open|filtered");
	return ("unknown");
}

/** Return the display name for one non-final runtime state. */
static const char	*probe_state_name(t_probe_state state)
{
	if (state == PROBE_PENDING)
		return ("pending");
	if (state == PROBE_QUEUED)
		return ("queued");
	if (state == PROBE_OUTSTANDING)
		return ("outstanding");
	if (state == PROBE_DONE)
		return ("done");
	return ("unknown");
}

/** Convert known ICMPv4 type/code pairs to concise report text. */
static const char	*icmp4_reason(uint8_t type, uint8_t code)
{
	if (type == 3 && code == 0)
		return ("net-unreachable");
	if (type == 3 && code == 1)
		return ("host-unreachable");
	if (type == 3 && code == 2)
		return ("protocol-unreachable");
	if (type == 3 && code == 3)
		return ("port-unreachable");
	if (type == 3 && code == 9)
		return ("net-prohibited");
	if (type == 3 && code == 10)
		return ("host-prohibited");
	if (type == 3 && code == 13)
		return ("admin-prohibited");
	if (type == 11 && code == 0)
		return ("ttl-exceeded");
	if (type == 11 && code == 1)
		return ("fragment-timeout");
	return (NULL);
}

/** Convert known ICMPv6 type/code pairs to concise report text. */
static const char	*icmp6_reason(uint8_t type, uint8_t code)
{
	if (type == 1 && code == 0)
		return ("no-route");
	if (type == 1 && code == 1)
		return ("admin-prohibited");
	if (type == 1 && code == 2)
		return ("beyond-scope");
	if (type == 1 && code == 3)
		return ("address-unreachable");
	if (type == 1 && code == 4)
		return ("port-unreachable");
	if (type == 1 && code == 5)
		return ("source-policy-failed");
	if (type == 1 && code == 6)
		return ("reject-route");
	if (type == 3 && code == 0)
		return ("hop-limit-exceeded");
	if (type == 3 && code == 1)
		return ("fragment-timeout");
	return (NULL);
}

/** Format the structured runtime reason without inventing protocol evidence. */
static void	format_scan_reason(const t_scan_reason *reason,
		char *buf, size_t size)
{
	const char	*name;

	if (!reason || size == 0)
		return ;
	if (reason->kind == SCAN_REASON_TCP)
	{
		if ((reason->tcp_flags & NMAP_TCP_SYN)
			&& (reason->tcp_flags & NMAP_TCP_ACK))
			snprintf(buf, size, "syn-ack");
		else if (reason->tcp_flags & NMAP_TCP_RST)
			snprintf(buf, size, "reset");
		else if (reason->tcp_flags & NMAP_TCP_SYN)
			snprintf(buf, size, "syn");
		else
			snprintf(buf, size, "tcp-flags-0x%02x", reason->tcp_flags);
		return ;
	}
	if (reason->kind == SCAN_REASON_UDP_REPLY)
		snprintf(buf, size, "udp-response");
	else if (reason->kind == SCAN_REASON_NO_RESPONSE)
		snprintf(buf, size, "no-response");
	else if (reason->kind == SCAN_REASON_SEND_ERROR)
		snprintf(buf, size, "send-error");
	else if (reason->kind == SCAN_REASON_ICMP)
	{
		name = NULL;
		if (reason->family == AF_INET)
			name = icmp4_reason(reason->icmp_type, reason->icmp_code);
		else if (reason->family == AF_INET6)
			name = icmp6_reason(reason->icmp_type, reason->icmp_code);
		if (name)
			snprintf(buf, size, "%s", name);
		else if (reason->family == AF_INET6)
			snprintf(buf, size, "icmp6-%u/%u",
				reason->icmp_type, reason->icmp_code);
		else
			snprintf(buf, size, "icmp-%u/%u",
				reason->icmp_type, reason->icmp_code);
	}
	else
		snprintf(buf, size, "none");
}

/** Check whether one scan column is enabled. */
static int	scan_enabled(const t_nmap_config *config, uint32_t scan_type)
{
	return ((config->scan.scan_mask & scan_type) != 0);
}

/** Find one logical probe by destination port and scan type. */
static t_probe	*find_probe(t_nmap_config *config,
		uint16_t port, uint32_t scan_type)
{
	size_t	i;

	i = 0;
	while (i < config->runtime.probe_count)
	{
		if (config->runtime.probes[i].dst_port == port
			&& config->runtime.probes[i].scan_type == scan_type)
			return (&config->runtime.probes[i]);
		i++;
	}
	return (NULL);
}

/** Display a final result when DONE, otherwise the live runtime state. */
static const char	*probe_display(const t_probe *probe)
{
	if (!probe)
		return ("unknown");
	if (probe->state != PROBE_DONE)
		return (probe_state_name(probe->state));
	return (scan_result_name(probe->result));
}

/** Return whether a DONE result counts as open-like for --open filtering. */
static int	probe_is_open_like(const t_probe *probe)
{
	if (!probe || probe->state != PROBE_DONE)
		return (0);
	return (probe->result == SCAN_RESULT_OPEN
		|| probe->result == SCAN_RESULT_OPEN_FILTERED);
}

/** Check whether any enabled scan keeps one port visible in --open mode. */
static int	port_is_open_like(t_nmap_config *config, uint16_t port)
{
	static const uint32_t	types[] = {
		NMAP_SCAN_SYN, NMAP_SCAN_NULL, NMAP_SCAN_FIN,
		NMAP_SCAN_XMAS, NMAP_SCAN_ACK, NMAP_SCAN_UDP
	};
	size_t				i;

	i = 0;
	while (i < sizeof(types) / sizeof(types[0]))
	{
		if (scan_enabled(config, types[i])
			&& probe_is_open_like(find_probe(config, port, types[i])))
			return (1);
		i++;
	}
	return (0);
}

/** Print one enabled result-table header column. */
static void	print_header_column(const t_nmap_config *config, uint32_t type)
{
	if (scan_enabled(config, type))
		printf("%-28s", scan_type_name(type));
}

/** Print one enabled result-table cell, optionally with --reason. */
static void	print_result_column(t_nmap_config *config,
		uint16_t port, uint32_t type)
{
	t_probe	*probe;
	char	reason[48];
	char	cell[96];

	if (!scan_enabled(config, type))
		return ;
	probe = find_probe(config, port, type);
	if (!config->scan.show_reason || !probe || probe->state != PROBE_DONE)
	{
		printf("%-28s", probe_display(probe));
		return ;
	}
	format_scan_reason(&probe->reason, reason, sizeof(reason));
	snprintf(cell, sizeof(cell), "%s(%s)", probe_display(probe), reason);
	printf("%-28s", cell);
}

/** Print the report table header in stable scan order. */
static void	print_header(const t_nmap_config *config)
{
	printf("%-8s", "PORT");
	print_header_column(config, NMAP_SCAN_SYN);
	print_header_column(config, NMAP_SCAN_NULL);
	print_header_column(config, NMAP_SCAN_FIN);
	print_header_column(config, NMAP_SCAN_XMAS);
	print_header_column(config, NMAP_SCAN_ACK);
	print_header_column(config, NMAP_SCAN_UDP);
	printf("\n");
}

/** Print all enabled scan results for one destination port. */
static void	print_port(t_nmap_config *config, uint16_t port)
{
	printf("%-8u", port);
	print_result_column(config, port, NMAP_SCAN_SYN);
	print_result_column(config, port, NMAP_SCAN_NULL);
	print_result_column(config, port, NMAP_SCAN_FIN);
	print_result_column(config, port, NMAP_SCAN_XMAS);
	print_result_column(config, port, NMAP_SCAN_ACK);
	print_result_column(config, port, NMAP_SCAN_UDP);
	printf("\n");
}

/** @brief Print the current-target scan report without modifying runtime state. */
void	nmap_print_report(t_nmap_config *config)
{
	size_t	i;

	if (!config)
		return ;
	printf("Scan report for %s (%s)\n",
		config->target.name, config->target.ip);
	printf("Probes: %zu total, %zu done, %zu queued, %zu outstanding\n\n",
		config->runtime.probe_count,
		config->runtime.done_count,
		config->runtime.queued_count,
		config->runtime.outstanding_count);
	print_header(config);
	i = 0;
	while (i < config->scan.port_count)
	{
		if (!config->scan.open_only
			|| port_is_open_like(config, config->scan.ports[i]))
			print_port(config, config->scan.ports[i]);
		i++;
	}
}
'''


RUN_C = r'''
#include "ft_nmap.h"
#include "debug/debug.h"

/**
 * @brief Execute the main event loop for the current resolved target.
 *
 * @note The main thread owns receive/match/classify/expire/schedule/wait.
 *       Sender workers only execute generations selected by the scheduler.
 */
static int	run_scan_loop(t_nmap_config *config, int *exit_status)
{
	while (!nmap_signal_stop_requested()
		&& !nmap_runtime_is_finished(config))
	{
		/* Consume replies before expiration to favor packets arriving on time. */
		if (!nmap_runtime_drain_replies(config, exit_status))
			return (0);
		nmap_runtime_expire_probes(config);
		if (!nmap_runtime_schedule_ready(config, exit_status))
			return (0);
		if (nmap_sender_pool_has_error(config))
		{
			if (exit_status)
				*exit_status = 1;
			return (0);
		}
		if (!nmap_runtime_wait(config, exit_status))
			return (0);
	}
	if (nmap_signal_stop_requested())
	{
		if (exit_status)
			*exit_status = 130;
		return (0);
	}
	/* A last worker may fail while simultaneously completing the final probe. */
	if (nmap_sender_pool_has_error(config))
	{
		if (exit_status)
			*exit_status = 1;
		return (0);
	}
	return (1);
}

/**
 * @brief Prepare, scan, report and clean one target.
 */
static int	run_target(t_nmap_config *config, const char *target,
		int *exit_status)
{
	int	success;

	success = 0;
	if (!nmap_prepare_target(config, target, exit_status)
		|| !nmap_prepare_route(config, exit_status)
		|| !nmap_prepare_send_socket(config, exit_status)
		|| !nmap_prepare_pcap(config, exit_status)
		|| !nmap_prepare_runtime(config, exit_status)
		|| !nmap_prepare_sender_pool(config, exit_status))
		goto cleanup;
	DEBUG_DEV_CONFIG(config);
	DEBUG_SOCKET(config);
	DEBUG_PCAP(config);
	DEBUG_RUNTIME(config);
	if (!run_scan_loop(config, exit_status))
		goto cleanup;
	/* Workers must be joined before report/cleanup can inspect/free probes. */
	nmap_stop_sender_pool(config);
	nmap_print_report(config);
	success = 1;
cleanup:
	nmap_cleanup_current_target(config);
	return (success);
}

/**
 * @brief Scan every prepared target and continue after target-local failures.
 */
int	nmap_run(t_nmap_config *config, int *exit_status)
{
	size_t	i;
	int		had_error;

	if (!config)
	{
		if (exit_status)
			*exit_status = 1;
		return (0);
	}
	i = 0;
	had_error = 0;
	while (i < config->targets.count)
	{
		if (nmap_signal_stop_requested())
		{
			if (exit_status)
				*exit_status = 130;
			return (0);
		}
		if (!run_target(config, config->targets.items[i], exit_status))
		{
			if (exit_status && *exit_status == 130)
				return (0);
			had_error = 1;
			if (exit_status)
				*exit_status = 0;
		}
		i++;
	}
	if (had_error && exit_status)
		*exit_status = 1;
	return (!had_error);
}
'''


PCAP_C = r'''
#include "config.h"

#include <pcap/pcap.h>
#include <stdio.h>
#include <string.h>

#define NMAP_PCAP_SNAPLEN 65535
#define NMAP_PCAP_TIMEOUT_MS 1
#define NMAP_PCAP_FILTER_SIZE 1024

/**
 * @brief Build the target-family BPF capture filter.
 *
 * Direct replies are restricted to target -> local traffic. ICMP errors may
 * come from intermediate routers, so the error branch only constrains the
 * destination. IPv6 uses protochain for ICMPv6 so extension headers in front
 * of ICMPv6 do not get discarded before the userspace Next Header walker.
 */
static int	build_pcap_filter(const t_nmap_config *config,
		char *filter, size_t filter_size)
{
	int	ret;

	if (config->target.addr.family == AF_INET)
	{
		ret = snprintf(filter, filter_size,
				"((ip and src host %s and dst host %s)"
				" or (icmp and dst host %s))",
				config->target.ip, config->route.src_ip,
				config->route.src_ip);
	}
	else if (config->target.addr.family == AF_INET6)
	{
		ret = snprintf(filter, filter_size,
				"((ip6 and src host %s and dst host %s)"
				" or (ip6 protochain 58 and dst host %s))",
				config->target.ip, config->route.src_ip,
				config->route.src_ip);
	}
	else
		return (0);
	return (ret >= 0 && (size_t)ret < filter_size);
}

/** Apply capture settings before activation. */
static int	apply_pcap_settings(pcap_t *handle)
{
	if (pcap_set_snaplen(handle, NMAP_PCAP_SNAPLEN) < 0)
		return (0);
	if (pcap_set_promisc(handle, 0) < 0)
		return (0);
	if (pcap_set_timeout(handle, NMAP_PCAP_TIMEOUT_MS) < 0)
		return (0);
	return (1);
}

/** Create and activate the pcap handle on the selected route interface. */
static int	open_pcap_handle(t_nmap_config *config)
{
	pcap_t	*handle;

	memset(config->capture.errbuf, 0, sizeof(config->capture.errbuf));
	handle = pcap_create(config->route.iface, config->capture.errbuf);
	if (!handle)
	{
		fprintf(stderr, "ft_nmap: pcap_create: %s\n",
			config->capture.errbuf);
		return (0);
	}
	if (!apply_pcap_settings(handle))
	{
		fprintf(stderr, "ft_nmap: pcap settings: %s\n", pcap_geterr(handle));
		pcap_close(handle);
		return (0);
	}
	if (pcap_activate(handle) < 0)
	{
		fprintf(stderr, "ft_nmap: pcap_activate: %s\n", pcap_geterr(handle));
		pcap_close(handle);
		return (0);
	}
	config->capture.handle = handle;
	return (1);
}

/** Compile and install the capture filter. */
static int	install_pcap_filter(t_nmap_config *config)
{
	struct bpf_program	program;
	char				filter[NMAP_PCAP_FILTER_SIZE];

	if (!build_pcap_filter(config, filter, sizeof(filter)))
	{
		fprintf(stderr, "ft_nmap: pcap filter too long\n");
		return (0);
	}
	if (pcap_compile(config->capture.handle, &program,
			filter, 1, PCAP_NETMASK_UNKNOWN) < 0)
	{
		fprintf(stderr, "ft_nmap: pcap_compile: %s\n",
			pcap_geterr(config->capture.handle));
		return (0);
	}
	if (pcap_setfilter(config->capture.handle, &program) < 0)
	{
		fprintf(stderr, "ft_nmap: pcap_setfilter: %s\n",
			pcap_geterr(config->capture.handle));
		pcap_freecode(&program);
		return (0);
	}
	pcap_freecode(&program);
	return (1);
}

/** Expose pcap as a non-blocking selectable fd for the event loop. */
static int	prepare_pcap_fd(t_nmap_config *config)
{
	config->capture.fd = pcap_get_selectable_fd(config->capture.handle);
	if (config->capture.fd < 0)
	{
		fprintf(stderr, "ft_nmap: pcap fd is not selectable\n");
		return (0);
	}
	if (pcap_setnonblock(config->capture.handle, 1,
			config->capture.errbuf) < 0)
	{
		fprintf(stderr, "ft_nmap: pcap_setnonblock: %s\n",
			config->capture.errbuf);
		return (0);
	}
	config->capture.datalink = pcap_datalink(config->capture.handle);
	return (1);
}

/** Prepare packet capture before the first probe is scheduled. */
int	nmap_prepare_pcap(t_nmap_config *config, int *exit_status)
{
	if (!config)
	{
		if (exit_status)
			*exit_status = 1;
		return (0);
	}
	memset(&config->capture, 0, sizeof(config->capture));
	config->capture.fd = -1;
	config->capture.datalink = -1;
	if (!open_pcap_handle(config)
		|| !install_pcap_filter(config)
		|| !prepare_pcap_fd(config))
	{
		if (config->capture.handle)
			pcap_close(config->capture.handle);
		config->capture.handle = NULL;
		config->capture.fd = -1;
		config->capture.datalink = -1;
		if (exit_status)
			*exit_status = 1;
		return (0);
	}
	return (1);
}
'''


ROUTE_C = r'''
#include "config.h"
#include "net/address.h"

#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/**
 * @brief Ask the kernel which source address it would route to the target.
 */
static int	find_source_address(const t_nmap_target *target,
		t_nmap_ip_addr *src_addr, int *saved_error)
{
	struct sockaddr_storage	dst;
	struct sockaddr_storage	local;
	socklen_t				dst_len;
	socklen_t				local_len;
	int						fd;
	int						error;

	if (!nmap_ip_to_sockaddr(&target->addr, 1, &dst, &dst_len))
	{
		*saved_error = EAFNOSUPPORT;
		return (0);
	}
	fd = socket(target->addr.family, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0)
	{
		*saved_error = errno;
		return (0);
	}
	if (connect(fd, (struct sockaddr *)&dst, dst_len) < 0)
	{
		error = errno;
		close(fd);
		*saved_error = error;
		return (0);
	}
	memset(&local, 0, sizeof(local));
	local_len = sizeof(local);
	if (getsockname(fd, (struct sockaddr *)&local, &local_len) < 0)
	{
		error = errno;
		close(fd);
		*saved_error = error;
		return (0);
	}
	close(fd);
	if (!nmap_ip_from_sockaddr(src_addr,
			(struct sockaddr *)&local, local_len))
	{
		*saved_error = EAFNOSUPPORT;
		return (0);
	}
	return (1);
}

/**
 * @brief Find the interface owning the selected source address.
 *
 * expected_ifindex is zero for ordinary unscoped routes. For a scoped IPv6
 * target it forces the local source-address match to occur on the same zone,
 * avoiding an address-only comparison across different interfaces.
 */
static int	find_source_interface(const t_nmap_ip_addr *src_addr,
		unsigned int expected_ifindex, char *iface, size_t iface_size,
		unsigned int *ifindex, int *saved_error)
{
	struct ifaddrs	*ifaddr;
	struct ifaddrs	*current;
	t_nmap_ip_addr	current_addr;
	unsigned int	current_ifindex;
	size_t			name_len;
	socklen_t		addr_len;
	int				found;

	ifaddr = NULL;
	if (getifaddrs(&ifaddr) < 0)
	{
		*saved_error = errno;
		return (0);
	}
	found = 0;
	current = ifaddr;
	while (current)
	{
		if (src_addr->family == AF_INET)
			addr_len = sizeof(struct sockaddr_in);
		else
			addr_len = sizeof(struct sockaddr_in6);
		current_ifindex = 0;
		if (current->ifa_name)
			current_ifindex = if_nametoindex(current->ifa_name);
		if (current->ifa_name && current->ifa_addr
			&& (current->ifa_flags & IFF_UP)
			&& current->ifa_addr->sa_family == src_addr->family
			&& current_ifindex != 0
			&& (expected_ifindex == 0
				|| current_ifindex == expected_ifindex)
			&& nmap_ip_from_sockaddr(&current_addr,
				current->ifa_addr, addr_len)
			&& nmap_ip_equal(src_addr, &current_addr))
		{
			name_len = strlen(current->ifa_name);
			if (name_len >= iface_size)
			{
				freeifaddrs(ifaddr);
				*saved_error = ENAMETOOLONG;
				return (0);
			}
			memcpy(iface, current->ifa_name, name_len + 1);
			*ifindex = current_ifindex;
			found = 1;
			break ;
		}
		current = current->ifa_next;
	}
	freeifaddrs(ifaddr);
	if (!found)
	{
		*saved_error = ENODEV;
		return (0);
	}
	return (1);
}

/**
 * @brief Prepare source address, interface and scope for the current target.
 */
int	nmap_prepare_route(t_nmap_config *config, int *exit_status)
{
	unsigned int	expected_ifindex;
	int				error;

	if (!config || (config->target.addr.family != AF_INET
			&& config->target.addr.family != AF_INET6))
	{
		if (exit_status)
			*exit_status = 1;
		return (0);
	}
	if (config->target.addr.family == AF_INET6
		&& IN6_IS_ADDR_LINKLOCAL(&config->target.addr.addr.v6)
		&& config->target.addr.scope_id == 0)
	{
		fprintf(stderr,
			"ft_nmap: link-local IPv6 target %s requires a zone "
			"identifier (for example %%eth0)\n", config->target.name);
		if (exit_status)
			*exit_status = 1;
		return (0);
	}
	memset(&config->route, 0, sizeof(config->route));
	error = 0;
	if (!find_source_address(&config->target,
			&config->route.src_addr, &error))
	{
		config->route.error = error;
		fprintf(stderr, "ft_nmap: no route to %s: %s\n",
			config->target.ip, strerror(error));
		if (exit_status)
			*exit_status = 1;
		return (0);
	}
	if (!nmap_ip_ntop(&config->route.src_addr,
			config->route.src_ip, sizeof(config->route.src_ip)))
	{
		config->route.error = errno;
		perror("ft_nmap: inet_ntop route source");
		if (exit_status)
			*exit_status = 1;
		return (0);
	}
	expected_ifindex = 0;
	if (config->target.addr.family == AF_INET6)
		expected_ifindex = config->target.addr.scope_id;
	if (expected_ifindex == 0 && config->route.src_addr.family == AF_INET6)
		expected_ifindex = config->route.src_addr.scope_id;
	if (!find_source_interface(&config->route.src_addr, expected_ifindex,
			config->route.iface, sizeof(config->route.iface),
			&config->route.ifindex, &error))
	{
		config->route.error = error;
		fprintf(stderr, "ft_nmap: cannot find interface for source %s: %s\n",
			config->route.src_ip, strerror(error));
		if (exit_status)
			*exit_status = 1;
		return (0);
	}
	return (1);
}
'''


def patch_small_files() -> None:
    replace_exact(
        "Makefile",
        "\tsrcs/parsing/pars_probes.c \\\n",
        "",
    )
    replace_exact(
        "inc/ft_nmap.h",
        "int\t\tparse_probes_per_thread(t_nmap_config *config,\n"
        "\t\t\tint argc, char **argv, int *i);\n",
        "",
    )
    replace_exact(
        "srcs/main.c",
        "\tprintf(\"  --probes-per-thread <n>    Send-window capacity per sender\\n\");\n",
        "",
    )
    replace_exact(
        "srcs/parsing/pars_flags.c",
        "\tif (nmap_streq(argv[*i], \"--probes-per-thread\"))\n"
        "\t\treturn (parse_probes_per_thread(config, argc, argv, i));\n",
        "",
    )


def patch_debug_names() -> None:
    path = ROOT / "srcs/debug/debug.c"
    text = path.read_text(encoding="utf-8")
    if "udp_dispatch_gap_ms" not in text:
        fail("udp_dispatch_gap_ms introuvable dans srcs/debug/debug.c")
    text = text.replace("udp_dispatch_gap_ms", "udp_send_gap_ms")
    old = "probe->seq, probe->attempts_sent,"
    new = (
        "probe->seq, (unsigned int)(probe->attempts_sent\n"
        "\t\t\t+ (probe->sending_dispatch_id != 0)),"
    )
    if old not in text:
        fail("attempts_sent de DEBUG_PROBE_SEND introuvable")
    text = text.replace(old, new, 1)
    path.write_text(text, encoding="utf-8")
    print("[patch]  srcs/debug/debug.c")


def main() -> None:
    require_repo()
    patch_small_files()
    patch_debug_names()
    remove("srcs/parsing/pars_probes.c")

    write("inc/config.h", CONFIG_H)
    write("inc/runtime.h", RUNTIME_H)
    write("srcs/init/prepare_scan_config.c", PREPARE_SCAN_CONFIG_C)
    write("srcs/runtime/runtime_internal.h", RUNTIME_INTERNAL_H)
    write("srcs/runtime/common.c", COMMON_C)
    write("srcs/runtime/scheduler.c", SCHEDULER_C)
    write("srcs/runtime/worker.c", WORKER_C)
    write("srcs/runtime/wait.c", WAIT_C)
    write("srcs/runtime/expire.c", EXPIRE_C)
    write("srcs/runtime/classify.c", CLASSIFY_C)
    write("srcs/runtime/recv.c", RECV_C)
    write("srcs/output/report.c", REPORT_C)
    write("srcs/run.c", RUN_C)
    write("srcs/net/pcap.c", PCAP_C)
    write("srcs/net/route.c", ROUTE_C)

    print()
    print("Refactor runtime P0/P1 applique.")
    print("- send generation race corrigee")
    print("- OUTSTANDING seulement apres sendto() reussi")
    print("- window globale decouplee du nombre de threads")
    print("- --probes-per-thread supprime")
    print("- UDP gap base sur le vrai send")
    print("- CLOCK_MONOTONIC pour le runtime")
    print("- ICMPv6/filter protochain corriges")
    print("- --reason conserve les faits protocolaires")
    print("- scope IPv6 link-local rendu explicite")


if __name__ == "__main__":
    main()