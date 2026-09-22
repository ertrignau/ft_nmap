
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

	if (config->runtime.timing.udp_send_gap_ms <= 0
		|| config->runtime.last_udp_sent_ms == 0)
		return (1);
	if (now_ms <= config->runtime.last_udp_sent_ms)
		return (0);
	elapsed = now_ms - config->runtime.last_udp_sent_ms;
	return (elapsed >= (uint64_t)config->runtime.timing.udp_send_gap_ms);
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

	/*
	 * --speedup is intentionally a naive threaded mode.
	 * Sender workers consume every PENDING probe without applying the
	 * inline network window or UDP pacing policy.
	 */
	if (config->sender_pool.worker_count > 0)
	{
		return (active_count_locked(config)
			< (size_t)config->sender_pool.worker_count);
	}

	if (active_count_locked(config) >= (size_t)config->scan.window_size)
		return (0);
	if (!nmap_probe_is_udp(probe))
		return (1);
	if (udp_active_count_locked(config)
		>= (size_t)config->runtime.timing.udp_window)
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
 * @brief Schedule every currently eligible PENDING probe.
 *
 * With --speedup 0, the main thread enforces the global window and UDP pacing.
 *
 * With --speedup N, those adaptive limits are deliberately bypassed: the N
 * workers themselves form the concurrency limit, with one outstanding probe
 * per worker.
 */
int	nmap_runtime_schedule_ready(t_nmap_config *config, int *exit_status)
{
	size_t		i;
	uint64_t	now_ms;
	int			threaded;

	if (!config)
	{
		if (exit_status)
			*exit_status = 1;
		return (0);
	}
	threaded = (config->sender_pool.worker_count > 0);
	if (!threaded && config->scan.window_size <= 0)
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
	i = 0;
	while (i < config->runtime.probe_count)
	{
		if (!threaded && global_window_full(config))
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
