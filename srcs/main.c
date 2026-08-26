#include "ft_nmap.h"
#include "debug/debug.h"

/**
 * @brief Program entry point and owner of the main event loop.
 *
 * @note The main thread exclusively owns pcap draining, matching,
 *       classification, expiration and scheduling. Sender threads only execute
 *       jobs selected by this loop.
 */
int	main(int ac, char **av)
{
	t_nmap_config	config;
	size_t			target_index;
	int				exit_status;

	exit_status = 0;
	if (!nmap_init_config(&config, av[0], &exit_status))
		return (exit_status);
	if (!nmap_signal_setup(&exit_status))
		goto cleanup;
	if (!nmap_parse_cli(&config, ac, av, &exit_status))
		goto cleanup;
	if (!nmap_prepare_scan_config(&config, &exit_status))
		goto cleanup;
	if (!nmap_prepare_targets(&config, &exit_status))
		goto cleanup;
	target_index = 0;
	while (target_index < config.targets.count
		&& !nmap_signal_stop_requested())
	{
		/*
		 * Family-dependent resources are deliberately prepared after target
		 * resolution. An IPv4 and an IPv6 target may therefore coexist in the
		 * same target list without keeping two permanent raw sockets open.
		 */
		if (!nmap_prepare_target(&config,
				config.targets.items[target_index], &exit_status)
			|| !nmap_prepare_route(&config, &exit_status)
			|| !nmap_prepare_send_socket(&config, &exit_status)
			|| !nmap_prepare_pcap(&config, &exit_status)
			|| !nmap_prepare_runtime(&config, &exit_status)
			|| !nmap_prepare_sender_pool(&config, &exit_status))
			goto cleanup;
		DEBUG_DEV_CONFIG(&config);
		DEBUG_SOCKET(&config);
		DEBUG_PCAP(&config);
		DEBUG_RUNTIME(&config);
		while (!nmap_signal_stop_requested() && !nmap_runtime_is_finished(&config))
		{
			/* Consume replies before expiring probes to favor on-time packets. */
			if (!nmap_runtime_drain_replies(&config, &exit_status))
				break ;
			nmap_runtime_expire_probes(&config);
			if (!nmap_runtime_schedule_ready(&config, &exit_status))
				break ;
			if (nmap_sender_pool_has_error(&config))
			{
				exit_status = 1;
				break ;
			}
			if (!nmap_runtime_wait(&config, &exit_status))
				break ;
		}
		if (nmap_signal_stop_requested())
			exit_status = 130;
		/* Join workers before report/cleanup can inspect or free probes. */
		nmap_stop_sender_pool(&config);
		nmap_print_report(&config);
		nmap_cleanup_current_target(&config);
		if (exit_status != 0)
			break ;
		target_index++;
	}
	if (nmap_signal_stop_requested())
		exit_status = 130;
	PROF_REPORT();
cleanup:
	nmap_cleanup_config(&config);
	return (exit_status);
}
