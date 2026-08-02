
#include "config.h"

#include <limits.h>
#include <stdio.h>

#define NMAP_DEFAULT_RETRIES 1
#define NMAP_MAX_RETRIES 10
#define NMAP_DEFAULT_TCP_TIMEOUT_MS 1000
#define NMAP_DEFAULT_UDP_TIMEOUT_MS 2500
#define NMAP_DEFAULT_PROBES_PER_THREAD 50
#define NMAP_MAX_PROBES_PER_THREAD 4096
#define NMAP_DEFAULT_SRC_PORT_BASE 40000
#define NMAP_DEFAULT_UDP_MAX_IN_FLIGHT 10
#define NMAP_DEFAULT_TCP_SEND_GAP_MS 0
#define NMAP_DEFAULT_UDP_DISPATCH_GAP_MS 50

#define NMAP_ALL_SCAN_TYPES \
	(NMAP_SCAN_SYN | NMAP_SCAN_NULL | NMAP_SCAN_FIN \
		| NMAP_SCAN_XMAS | NMAP_SCAN_ACK | NMAP_SCAN_UDP)

/**
 * @brief Fill the mandatory default port range.
 *
 * @param scan Effective scan configuration.
 */
static void	set_default_ports(t_nmap_scan *scan)
{
	size_t	index;

	index = 0;
	while (index < NMAP_MAX_PORTS)
	{
		scan->ports[index] = (uint16_t)(index + 1);
		index++;
	}
	scan->port_count = NMAP_MAX_PORTS;
}

/**
 * @brief Prepare the effective port and scan selections.
 *
 * @param config Global nmap configuration.
 *
 * @return 1 on success, 0 on invalid parsed values.
 */
static int	prepare_scan_selection(t_nmap_config *config)
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
	if ((config->scan.scan_mask & ~NMAP_ALL_SCAN_TYPES) != 0
		|| config->scan.scan_mask == 0)
	{
		fprintf(stderr, "ft_nmap: invalid scan mask\n");
		return (0);
	}
	return (1);
}

/**
 * @brief Prepare thread, retry and timeout settings.
 *
 * @param config Global nmap configuration.
 *
 * @return 1 on success, 0 on invalid parsed values.
 */
static int	prepare_runtime_limits(t_nmap_config *config)
{
	int	sender_count;
	int	probes_per_sender;

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
	if (config->cli.probes_per_thread_specified)
		probes_per_sender = config->cli.probes_per_thread;
	else
		probes_per_sender = NMAP_DEFAULT_PROBES_PER_THREAD;
	if (probes_per_sender <= 0
		|| probes_per_sender > NMAP_MAX_PROBES_PER_THREAD)
	{
		fprintf(stderr, "ft_nmap: invalid probes-per-thread value\n");
		return (0);
	}
	config->scan.max_outstanding_per_sender = probes_per_sender;
	sender_count = config->scan.thread_count;
	if (sender_count == 0)
		sender_count = 1;
	if (probes_per_sender > INT_MAX / sender_count)
	{
		fprintf(stderr, "ft_nmap: in-flight limit overflow\n");
		return (0);
	}
	config->scan.max_in_flight = probes_per_sender * sender_count;
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
	return (1);
}

/**
 * @brief Prepare effective feature and pacing options.
 *
 * @param config Global nmap configuration.
 */
static void	prepare_feature_options(t_nmap_config *config)
{
	config->scan.src_port_base = NMAP_DEFAULT_SRC_PORT_BASE;
	config->scan.udp_max_in_flight = NMAP_DEFAULT_UDP_MAX_IN_FLIGHT;
	if (config->scan.udp_max_in_flight > config->scan.max_in_flight)
		config->scan.udp_max_in_flight = config->scan.max_in_flight;
	config->scan.tcp_send_gap_ms = NMAP_DEFAULT_TCP_SEND_GAP_MS;
	config->scan.udp_dispatch_gap_ms = NMAP_DEFAULT_UDP_DISPATCH_GAP_MS;
	config->scan.no_dns = config->cli.no_dns;
	config->scan.version_detection = config->cli.version_detection;
	config->scan.os_detection = config->cli.os_detection;
	config->scan.open_only = config->cli.open_only;
	config->scan.show_reason = config->cli.show_reason;
}

/**
 * @brief Build the effective scan configuration from parsed CLI options.
 *
 * @param config Global nmap configuration.
 * @param exit_status Output exit status set on invalid configuration.
 *
 * @return 1 on success, 0 on failure.
 *
 * @note The parser records user input. This function applies defaults and
 *       derives the limits consumed by the runtime, scheduler and workers.
 */
int	nmap_prepare_scan_config(t_nmap_config *config, int *exit_status)
{
	if (!config
		|| !prepare_scan_selection(config)
		|| !prepare_runtime_limits(config))
	{
		if (exit_status)
			*exit_status = 1;
		return (0);
	}
	prepare_feature_options(config);
	return (1);
}
