#include "config.h"
#include "debug/debug.h"

#include <errno.h>
#include <stdio.h>
#include <sys/select.h>
#include <sys/time.h>

/**
 * @brief Return current time in microseconds.
 *
 * @return Current timestamp in microseconds.
 */
static uint64_t	get_time_us(void)
{
	struct timeval	tv;

	gettimeofday(&tv, NULL);
	return ((uint64_t)tv.tv_sec * 1000000ULL + (uint64_t)tv.tv_usec);
}

/**
 * @brief Convert milliseconds to struct timeval.
 *
 * @param ms Duration in milliseconds.
 * @param timeout Destination timeval.
 */
static void	set_timeout_ms(uint64_t ms, struct timeval *timeout)
{
	timeout->tv_sec = ms / 1000;
	timeout->tv_usec = (ms % 1000) * 1000;
}

/**
 * @brief Return the timeout for a specific probe.
 *
 * @param config Global nmap configuration.
 * @param probe Probe to inspect.
 *
 * @return Timeout in milliseconds.
 */
static int	get_probe_timeout_ms(t_nmap_config *config, t_probe *probe)
{
	if (probe->scan_type == NMAP_SCAN_UDP)
		return (config->scan.udp_timeout_ms);
	return (config->scan.tcp_timeout_ms);
}

/**
 * @brief Compute remaining time before one probe expires.
 *
 * @param probe In-flight runtime probe.
 * @param now_ms Current timestamp in milliseconds.
 * @param timeout_ms Configured probe timeout in milliseconds.
 *
 * @return Remaining milliseconds before timeout, or 0 if already expired.
 */
static uint64_t	get_probe_remaining_ms(t_probe *probe,
		uint64_t now_ms, int timeout_ms)
{
	uint64_t	elapsed_ms;

	if (timeout_ms <= 0)
		return (0);
	if (now_ms <= probe->sent_at_ms)
		return ((uint64_t)timeout_ms);
	elapsed_ms = now_ms - probe->sent_at_ms;
	if (elapsed_ms >= (uint64_t)timeout_ms)
		return (0);
	return ((uint64_t)timeout_ms - elapsed_ms);
}

/**
 * @brief Return remaining UDP pacing delay.
 *
 * @param config Global nmap configuration.
 * @param now_ms Current timestamp in milliseconds.
 *
 * @return Remaining milliseconds before next UDP dispatch is allowed.
 */
static uint64_t	get_udp_gap_remaining_ms(t_nmap_config *config, uint64_t now_ms)
{
	uint64_t	elapsed;

	if (config->scan.udp_dispatch_gap_ms <= 0)
		return (0);
	if (config->runtime.last_udp_dispatch_ms == 0)
		return (0);
	elapsed = now_ms - config->runtime.last_udp_dispatch_ms;
	if (elapsed >= (uint64_t)config->scan.udp_dispatch_gap_ms)
		return (0);
	return ((uint64_t)config->scan.udp_dispatch_gap_ms - elapsed);
}

/**
 * @brief Register a candidate wait duration.
 *
 * @param wait_ms Destination wait duration.
 * @param found Whether a previous wait was already found.
 * @param candidate_ms Candidate duration in milliseconds.
 */
static void	update_wait_ms(uint64_t *wait_ms, int *found,
		uint64_t candidate_ms)
{
	if (!*found || candidate_ms < *wait_ms)
		*wait_ms = candidate_ms;
	*found = 1;
}

/**
 * @brief Find the next useful scheduler wait while runtime_lock is held.
 *
 * @param config Global nmap configuration.
 * @param wait_ms Destination wait duration in milliseconds.
 * @param now_us Output timestamp used to compute this wait.
 *
 * @return 1 if a wait is useful, 0 otherwise.
 */
static int	get_next_wait_ms_locked(t_nmap_config *config,
		uint64_t *wait_ms, uint64_t *now_us)
{
	size_t		i;
	uint64_t	now_ms;
	uint64_t	remaining_ms;
	int			found;

	if (!now_us)
		return (0);
	*now_us = get_time_us();
	now_ms = *now_us / 1000;
	found = 0;
	if (config->runtime.queued_count > 0)
		update_wait_ms(wait_ms, &found, 1);
	i = 0;
	while (i < config->runtime.probe_count)
	{
		if (config->runtime.probes[i].state == PROBE_IN_FLIGHT)
		{
			remaining_ms = get_probe_remaining_ms(&config->runtime.probes[i],
					now_ms,
					get_probe_timeout_ms(config, &config->runtime.probes[i]));
			update_wait_ms(wait_ms, &found, remaining_ms);
		}
		i++;
	}
	remaining_ms = get_udp_gap_remaining_ms(config, now_ms);
	if (remaining_ms > 0)
		update_wait_ms(wait_ms, &found, remaining_ms);
	return (found);
}

/**
 * @brief Find the next useful scheduler wait.
 *
 * @param config Global nmap configuration.
 * @param wait_ms Destination wait duration in milliseconds.
 * @param now_us Output timestamp used to compute this wait.
 *
 * @return 1 if a wait is useful, 0 otherwise.
 */
static int	get_next_wait_ms(t_nmap_config *config,
		uint64_t *wait_ms, uint64_t *now_us)
{
	int	found;

	pthread_mutex_lock(&config->sender_pool.runtime_lock);
	found = get_next_wait_ms_locked(config, wait_ms, now_us);
	pthread_mutex_unlock(&config->sender_pool.runtime_lock);
	return (found);
}

/**
 * @brief Wait for the next useful runtime event.
 *
 * @param config Global nmap configuration.
 * @param exit_status Output exit status set on fatal select error.
 *
 * @return 1 on success, 0 on fatal select error.
 *
 * @note This waits on the pcap fd, but never longer than the next probe
 *       timeout, a queued worker transition, or UDP pacing deadline. EINTR is
 *       not fatal because SIGINT is handled by the main loop.
 */
int	nmap_runtime_wait(t_nmap_config *config, int *exit_status)
{
	fd_set			readfds;
	struct timeval	timeout;
	uint64_t		wait_ms;
	uint64_t		now_us;
	uint64_t		after_us;
	int				ret;

	if (!config || config->capture.fd < 0)
	{
		if (exit_status)
			*exit_status = 1;
		return (0);
	}
	if (!get_next_wait_ms(config, &wait_ms, &now_us))
		return (1);
	FD_ZERO(&readfds);
	FD_SET(config->capture.fd, &readfds);
	set_timeout_ms(wait_ms, &timeout);
	ret = select(config->capture.fd + 1, &readfds, NULL, NULL, &timeout);
	after_us = get_time_us();
	PROF_ADD_VALUE(NMAP_PROF_SELECT_REQUESTED, wait_ms * 1000ULL);
	PROF_ADD_VALUE(NMAP_PROF_SELECT_WAIT, after_us - now_us);
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
