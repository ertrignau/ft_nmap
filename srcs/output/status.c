/* NMAP_OUTPUT_STATUS_V1 */

#include "config.h"
#include "output/output_internal.h"

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static uint64_t	g_scan_started_ms;

/** Return monotonic time in milliseconds. */
static uint64_t	output_now_ms(void)
{
	struct timespec	ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return (0);
	return ((uint64_t)ts.tv_sec * 1000ULL
		+ (uint64_t)ts.tv_nsec / 1000000ULL);
}

/** Return whether the selected ports form one continuous range. */
static int	ports_are_contiguous(const t_nmap_config *config)
{
	size_t	i;

	if (!config || config->scan.port_count == 0)
		return (0);
	i = 1;
	while (i < config->scan.port_count)
	{
		if (config->scan.ports[i]
			!= (uint16_t)(config->scan.ports[i - 1] + 1))
			return (0);
		i++;
	}
	return (1);
}

/** Print the selected ports without flooding the terminal. */
static void	print_ports(const t_nmap_config *config)
{
	size_t	i;

	printf("Ports    : ");
	if (config->scan.port_count == 1)
	{
		printf("%u (1 port)\n", config->scan.ports[0]);
		return ;
	}
	if (ports_are_contiguous(config))
	{
		printf("%u-%u (%zu ports)\n",
			config->scan.ports[0],
			config->scan.ports[config->scan.port_count - 1],
			config->scan.port_count);
		return ;
	}
	if (config->scan.port_count <= 12)
	{
		i = 0;
		while (i < config->scan.port_count)
		{
			if (i != 0)
				printf(",");
			printf("%u", config->scan.ports[i]);
			i++;
		}
		printf(" (%zu ports)\n", config->scan.port_count);
		return ;
	}
	printf("%zu selected ports\n", config->scan.port_count);
}

/** Print one enabled scan name. */
static void	print_scan(uint32_t mask, uint32_t scan,
		const char *name, int *first)
{
	if ((mask & scan) == 0)
		return ;
	if (!*first)
		printf(",");
	printf("%s", name);
	*first = 0;
}

/** Print all enabled scan names. */
static void	print_scans(const t_nmap_config *config)
{
	int	first;

	first = 1;
	printf("Scans    : ");
	print_scan(config->scan.scan_mask, NMAP_SCAN_SYN, "SYN", &first);
	print_scan(config->scan.scan_mask, NMAP_SCAN_NULL, "NULL", &first);
	print_scan(config->scan.scan_mask, NMAP_SCAN_FIN, "FIN", &first);
	print_scan(config->scan.scan_mask, NMAP_SCAN_XMAS, "XMAS", &first);
	print_scan(config->scan.scan_mask, NMAP_SCAN_ACK, "ACK", &first);
	print_scan(config->scan.scan_mask, NMAP_SCAN_UDP, "UDP", &first);
	printf("\n");
}

/** Print the effective timeout policy. */
static void	print_timeouts(const t_nmap_config *config)
{
	uint32_t	tcp_mask;
	int			has_tcp;
	int			has_udp;

	tcp_mask = NMAP_SCAN_SYN | NMAP_SCAN_NULL | NMAP_SCAN_FIN
		| NMAP_SCAN_XMAS | NMAP_SCAN_ACK;
	has_tcp = ((config->scan.scan_mask & tcp_mask) != 0);
	has_udp = ((config->scan.scan_mask & NMAP_SCAN_UDP) != 0);
	if (has_tcp && has_udp)
		printf("Timeouts : TCP %d ms / UDP %d ms\n",
			config->scan.tcp_timeout_ms,
			config->scan.udp_timeout_ms);
	else if (has_udp)
		printf("Timeout  : %d ms\n",
			config->scan.udp_timeout_ms);
	else
		printf("Timeout  : %d ms\n",
			config->scan.tcp_timeout_ms);
}

/** Format milliseconds as H:MM:SS. */
static void	format_duration(uint64_t ms, char *buffer, size_t size)
{
	uint64_t	total;
	uint64_t	hours;
	uint64_t	minutes;
	uint64_t	seconds;

	total = ms / 1000ULL;
	hours = total / 3600ULL;
	minutes = (total % 3600ULL) / 60ULL;
	seconds = total % 60ULL;
	snprintf(buffer, size, "%llu:%02llu:%02llu",
		(unsigned long long)hours,
		(unsigned long long)minutes,
		(unsigned long long)seconds);
}

/**
 * @brief Print Estimated Time of Completion.
 *
 * ETC means Estimated Time of Completion.
 */
static void	print_etc(uint64_t remaining_ms)
{
	time_t		finish;
	struct tm	local;
	char		buffer[16];

	finish = time(NULL) + (time_t)(remaining_ms / 1000ULL);
	if (!localtime_r(&finish, &local))
		return ;
	if (strftime(buffer, sizeof(buffer), "%H:%M", &local) == 0)
		return ;
	printf("%s", buffer);
}

/** Print effective configuration and start progress timing. */
void	nmap_output_begin_scan(const t_nmap_config *config)
{
	if (!config)
		return ;
	g_scan_started_ms = output_now_ms();

	printf("ft_nmap scan configuration\n");
	if (config->target.name
		&& strcmp(config->target.name, config->target.ip) != 0)
		printf("Target   : %s (%s)\n",
			config->target.name,
			config->target.ip);
	else
		printf("Target   : %s\n", config->target.ip);

	print_ports(config);
	print_scans(config);

	printf("Threads  : %d\n", config->scan.thread_count);
	printf("Retries  : %d\n", config->scan.retries);
	print_timeouts(config);
	printf("Window   : %d\n", config->scan.window_size);

	if (isatty(STDIN_FILENO))
		printf("\nStarting scan... (press Enter for progress)\n\n");
	else
		printf("\nStarting scan...\n\n");

	fflush(stdout);
}

/** Print one coherent snapshot of the current runtime counters. */
void	nmap_output_print_progress(t_nmap_config *config)
{
	size_t		total;
	size_t		done;
	size_t		queued;
	size_t		outstanding;
	size_t		pending;
	uint64_t	now;
	uint64_t	elapsed;
	uint64_t	remaining;
	double		percent;
	char		elapsed_text[32];
	char		remaining_text[32];

	if (!config)
		return ;

	pthread_mutex_lock(&config->runtime.lock);
	total = config->runtime.probe_count;
	done = config->runtime.done_count;
	queued = config->runtime.queued_count;
	outstanding = config->runtime.outstanding_count;
	pthread_mutex_unlock(&config->runtime.lock);

	pending = 0;
	if (total >= done + queued + outstanding)
		pending = total - done - queued - outstanding;

	now = output_now_ms();
	elapsed = 0;
	if (g_scan_started_ms != 0 && now >= g_scan_started_ms)
		elapsed = now - g_scan_started_ms;

	percent = 0.0;
	if (total != 0)
		percent = (double)done * 100.0 / (double)total;

	format_duration(elapsed,
		elapsed_text, sizeof(elapsed_text));

	printf("Stats: %s elapsed; "
		"%zu/%zu probes completed (%.1f%%); "
		"%zu outstanding; %zu queued; %zu pending\n",
		elapsed_text,
		done,
		total,
		percent,
		outstanding,
		queued,
		pending);

	if (done == 0 || done >= total)
	{
		printf("Timing: About %.1f%% done\n", percent);
		fflush(stdout);
		return ;
	}

	remaining = (uint64_t)(((long double)elapsed
			* (long double)(total - done))
			/ (long double)done);

	format_duration(remaining,
		remaining_text, sizeof(remaining_text));

	printf("Timing: About %.1f%% done; ETC: ", percent);
	print_etc(remaining);
	printf(" (%s remaining)\n", remaining_text);

	fflush(stdout);
}
