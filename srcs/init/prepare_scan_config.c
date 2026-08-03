#include "config.h"

#define NMAP_DEFAULT_TIMEOUT_MS 1000
#define NMAP_DEFAULT_MAX_IN_FLIGHT 50

#define NMAP_DEFAULT_SCAN_MASK \
	(NMAP_SCAN_SYN | NMAP_SCAN_NULL | NMAP_SCAN_FIN \
		| NMAP_SCAN_XMAS | NMAP_SCAN_ACK | NMAP_SCAN_UDP)

/**
 * @brief Build the effective scan configuration from parsed CLI options.
 *
 * @param config Global nmap configuration.
 * @param exit_status Output exit status set on configuration error.
 *
 * @return 1 on success, 0 on invalid configuration.
 *
 * @note The parser only records options explicitly provided by the user.
 *       Defaults used by the scan engine are applied here.
 */
int	nmap_prepare_scan_config(t_nmap_config *config, int *exit_status)
{
	if (!config)
	{
		if (exit_status)
			*exit_status = 1;
		return (0);
	}
	if (config->cli.scan_specified)
		config->scan.scan_mask = config->cli.scan_mask;
	else
		config->scan.scan_mask = NMAP_DEFAULT_SCAN_MASK;
	if (config->cli.timeout_specified)
		config->scan.timeout_ms = config->cli.timeout_ms;
	else
		config->scan.timeout_ms = NMAP_DEFAULT_TIMEOUT_MS;
	if (config->cli.probes_per_thread_specified)
		config->scan.max_outstanding_per_worker
			= config->cli.probes_per_thread;
	else
		config->scan.max_outstanding_per_worker = 1;
	config->scan.max_in_flight = NMAP_DEFAULT_MAX_IN_FLIGHT;
	return (1);
}