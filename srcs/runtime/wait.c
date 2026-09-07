
#include "config.h"
#include "debug/debug.h"
#include "runtime/runtime_internal.h"

#include <errno.h>
#include <stdio.h>
#include <sys/select.h>
#include <sys/time.h>
#include <time.h>
#include "output/output_internal.h"
#include <unistd.h>

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
	static int		stdin_available = 1;
	fd_set			readfds;
	struct timeval	timeout;
	uint64_t		wait_ms;
	uint64_t		before_us;
	uint64_t		after_us;
	int				ret;
	int			max_fd;
	int			watch_stdin;
	char		input[64];
	ssize_t		input_size;

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
	max_fd = config->capture.fd;
	watch_stdin = (stdin_available && isatty(STDIN_FILENO));
	if (watch_stdin)
	{
		FD_SET(STDIN_FILENO, &readfds);
		if (STDIN_FILENO > max_fd)
			max_fd = STDIN_FILENO;
	}
	set_timeval(wait_ms, &timeout);
	ret = select(max_fd + 1,
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
	if (ret > 0 && watch_stdin
		&& FD_ISSET(STDIN_FILENO, &readfds))
	{
		input_size = read(STDIN_FILENO, input, sizeof(input));
		if (input_size > 0)
			nmap_output_print_progress(config);
		else
			stdin_available = 0;
	}

	return (1);
}
