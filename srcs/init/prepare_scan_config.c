/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   prepare_scan_config.c                              :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: eric <eric@student.42.fr>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2026/08/03 16:09:40 by eric              #+#    #+#             */
/*   Updated: 2026/08/20 14:55:51 by eric             ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "config.h"

#include <limits.h>
#include <stdio.h>

#define NMAP_DEFAULT_RETRIES 1
#define NMAP_MAX_RETRIES 10
#define NMAP_DEFAULT_TCP_TIMEOUT_MS 1000
#define NMAP_DEFAULT_UDP_TIMEOUT_MS 2500
#define NMAP_DEFAULT_WINDOW_PER_SENDER 50
#define NMAP_MAX_WINDOW_PER_SENDER 4096
#define NMAP_DEFAULT_UDP_WINDOW 10
#define NMAP_DEFAULT_UDP_DISPATCH_GAP_MS 50

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
 * @note The window is deliberately centralized here instead of in workers.
 *       A later adaptive congestion controller can replace this policy without
 *       changing packet senders or thread ownership.
 */
static int	prepare_timing(t_nmap_config *config)
{
	int	senders;
	int	per_sender;

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
	if (config->cli.probes_per_thread_specified)
		per_sender = config->cli.probes_per_thread;
	else
		per_sender = NMAP_DEFAULT_WINDOW_PER_SENDER;
	if (per_sender <= 0 || per_sender > NMAP_MAX_WINDOW_PER_SENDER)
	{
		fprintf(stderr, "ft_nmap: invalid probes-per-thread value\n");
		return (0);
	}
	senders = config->scan.thread_count;
	if (senders == 0)
		senders = 1;
	if (per_sender > INT_MAX / senders)
	{
		fprintf(stderr, "ft_nmap: send window overflow\n");
		return (0);
	}
	config->scan.window_size = per_sender * senders;
	config->scan.udp_window_size = NMAP_DEFAULT_UDP_WINDOW;
	if (config->scan.udp_window_size > config->scan.window_size)
		config->scan.udp_window_size = config->scan.window_size;
	config->scan.udp_dispatch_gap_ms = NMAP_DEFAULT_UDP_DISPATCH_GAP_MS;
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
 * @brief Convert parsed CLI values into the immutable scan plan.
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
