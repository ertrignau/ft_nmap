#include "config.h"

#include <errno.h>
#include <stdio.h>
#include <sys/select.h>
#include <sys/time.h>

/**
 * @brief Return current time in milliseconds.
 *
 * @return Current timestamp in milliseconds.
 */
static uint64_t	get_time_ms(void)
{
	struct timeval	tv;

	gettimeofday(&tv, NULL);
	return ((uint64_t)tv.tv_sec * 1000 + (uint64_t)tv.tv_usec / 1000);
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
 * @brief Find the next in-flight probe timeout.
 *
 * @param config Global nmap configuration.
 * @param wait_ms Destination wait duration in milliseconds.
 *
 * @return 1 if an in-flight timeout exists, 0 otherwise.
 */
static int	get_next_timeout_ms(t_nmap_config *config, uint64_t *wait_ms)
{
	size_t		i;
	uint64_t	now_ms;
	uint64_t	remaining_ms;
	int			found;

	now_ms = get_time_ms();
	found = 0;
	i = 0;
	while (i < config->runtime.probe_count)
	{
		if (config->runtime.probes[i].state == PROBE_IN_FLIGHT)
		{
			remaining_ms = get_probe_remaining_ms(&config->runtime.probes[i],
					now_ms, config->scan.timeout_ms);
			if (!found || remaining_ms < *wait_ms)
				*wait_ms = remaining_ms;
			found = 1;
		}
		i++;
	}
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
 *       timeout. EINTR is not fatal because SIGINT is handled by the main loop.
 */
int	nmap_runtime_wait(t_nmap_config *config, int *exit_status)
{
	fd_set			readfds;
	struct timeval	timeout;
	uint64_t		wait_ms;
	int				ret;

	if (!config || config->capture.fd < 0)
	{
		if (exit_status)
			*exit_status = 1;
		return (0);
	}
	if (!get_next_timeout_ms(config, &wait_ms))
		return (1);
	FD_ZERO(&readfds);
	FD_SET(config->capture.fd, &readfds);
	set_timeout_ms(wait_ms, &timeout);
	ret = select(config->capture.fd + 1, &readfds, NULL, NULL, &timeout);
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