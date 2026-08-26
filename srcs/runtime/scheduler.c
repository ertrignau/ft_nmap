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

/** Check whether the global UDP dispatch gap has elapsed. */
static int	udp_gap_allows_locked(const t_nmap_config *config,
		uint64_t now_ms)
{
	uint64_t	elapsed;

	if (config->scan.udp_dispatch_gap_ms <= 0
		|| config->runtime.last_udp_dispatch_ms == 0)
		return (1);
	elapsed = now_ms - config->runtime.last_udp_dispatch_ms;
	return (elapsed >= (uint64_t)config->scan.udp_dispatch_gap_ms);
}

/**
 * @brief Check whether one PENDING probe can consume scheduler capacity now.
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
	return (udp_gap_allows_locked(config, now_ms));
}

/** Reserve one threaded send job and create a fresh dispatch generation. */
static uint32_t	reserve_threaded_locked(t_nmap_config *config,
		t_probe *probe, uint64_t now_ms)
{
	probe->state = PROBE_QUEUED;
	probe->dispatch_id++;
	config->runtime.queued_count++;
	if (nmap_probe_is_udp(probe))
	{
		config->runtime.udp_queued_count++;
		config->runtime.last_udp_dispatch_ms = now_ms;
	}
	return (probe->dispatch_id);
}

/**
 * @brief Start one inline attempt immediately before the packet-layer send.
 */
static void	reserve_inline_locked(t_nmap_config *config,
		t_probe *probe, uint64_t now_ms)
{
	probe->state = PROBE_OUTSTANDING;
	probe->attempts_sent++;
	probe->sent_at_ms = now_ms;
	config->runtime.outstanding_count++;
	if (nmap_probe_is_udp(probe))
	{
		config->runtime.udp_outstanding_count++;
		config->runtime.last_udp_dispatch_ms = now_ms;
	}
}

/** Undo a QUEUED reservation if the sender-pool queue cannot accept the job. */
static void	revert_threaded_reservation(t_nmap_config *config,
		t_probe *probe, uint32_t dispatch_id)
{
	pthread_mutex_lock(&config->runtime.lock);
	if (probe->state == PROBE_QUEUED
		&& probe->dispatch_id == dispatch_id)
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

/**
 * @brief Send one selected probe directly from the main thread.
 */
static int	send_inline(t_nmap_config *config, t_probe *probe,
		uint64_t now_ms, int *exit_status)
{
	pthread_mutex_lock(&config->runtime.lock);
	if (!probe_can_be_reserved_locked(config, probe, now_ms))
	{
		pthread_mutex_unlock(&config->runtime.lock);
		return (1);
	}
	reserve_inline_locked(config, probe, now_ms);
	pthread_mutex_unlock(&config->runtime.lock);
	DEBUG_PROBE_SEND(probe);
	if (!nmap_send_probe(config, probe))
	{
		nmap_mark_probe_done(config, probe,
			SCAN_RESULT_UNKNOWN, SCAN_REASON_SEND_ERROR, "send failure");
		if (exit_status)
			*exit_status = 1;
		return (0);
	}
	return (1);
}

/**
 * @brief Reserve and enqueue one probe for sender-thread execution.
 */
static int	queue_threaded(t_nmap_config *config, t_probe *probe,
		uint64_t now_ms, int *exit_status)
{
	uint32_t	dispatch_id;

	pthread_mutex_lock(&config->runtime.lock);
	if (!probe_can_be_reserved_locked(config, probe, now_ms))
	{
		pthread_mutex_unlock(&config->runtime.lock);
		return (1);
	}
	dispatch_id = reserve_threaded_locked(config, probe, now_ms);
	pthread_mutex_unlock(&config->runtime.lock);
	if (!nmap_dispatch_probe_to_sender(config, probe, dispatch_id))
	{
		revert_threaded_reservation(config, probe, dispatch_id);
		if (nmap_sender_pool_has_error(config))
		{
			if (exit_status)
				*exit_status = 1;
			return (0);
		}
	}
	return (1);
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
 * @note This function is the only owner of send-order/window policy. Workers
 *       do not decide what to send and cannot bypass UDP/global limits.
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
