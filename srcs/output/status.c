#include "output/output_internal.h"

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

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

/** Print Estimated Time of Completion. */
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

/** Print effective configuration before one target scan. */
void	nmap_output_begin_scan(const t_nmap_config *config)
{
	if (!config)
		return ;
	printf("ft_nmap scan configuration\n");
	if (config->target.name
		&& strcmp(config->target.name, config->target.ip) != 0)
		printf("Target   : %s (%s)\n",
			config->target.name, config->target.ip);
	else
		printf("Target   : %s\n", config->target.ip);
	print_ports(config);
	print_scans(config);
	printf("Extra threads : %d\n", config->scan.thread_count);
	printf("Retries       : %d\n", config->scan.retries);
	print_timeouts(config);
	if (config->scan.thread_count > 0)
		printf("Send mode     : naive threaded\n");
	else
		printf("Window        : %d\n", config->scan.window_size);
	if (isatty(STDIN_FILENO))
		printf("\nStarting scan... (press Enter for progress)\n\n");
	else
		printf("\nStarting scan...\n\n");
	fflush(stdout);
}

/** Print one immutable progress snapshot. */
void	nmap_output_print_progress(const t_nmap_progress *progress)
{
	uint64_t	remaining;
	double		percent;
	char		elapsed[32];
	char		remaining_text[32];

	if (!progress)
		return ;
	percent = 0.0;
	if (progress->total != 0)
		percent = (double)progress->done
			* 100.0 / (double)progress->total;
	nmap_output_format_hms(progress->elapsed_ms,
		elapsed, sizeof(elapsed));
	printf("Stats: %s elapsed; %zu/%zu probes completed (%.1f%%); "
		"%zu outstanding; %zu queued; %zu benched; %zu pending\n",
		elapsed, progress->done, progress->total, percent,
		progress->outstanding, progress->queued,
		progress->benched, progress->pending);
	if (progress->done == 0 || progress->done >= progress->total)
	{
		printf("Timing: About %.1f%% done\n", percent);
		fflush(stdout);
		return ;
	}
	remaining = (uint64_t)(((long double)progress->elapsed_ms
			* (long double)(progress->total - progress->done))
			/ (long double)progress->done);
	nmap_output_format_hms(remaining,
		remaining_text, sizeof(remaining_text));
	printf("Timing: About %.1f%% done; ETC: ", percent);
	print_etc(remaining);
	printf(" (%s remaining)\n", remaining_text);
	fflush(stdout);
}
