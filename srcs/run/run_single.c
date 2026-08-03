/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   run_single.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: eric <eric@student.42.fr>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2026/08/03 15:17:25 by eric              #+#    #+#             */
/*   Updated: 2026/08/03 15:26:45 by eric             ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"
#include "debug/debug.h"

static int	run_scan_loop(t_nmap_config *config, int *exit_status)
{
	while (!nmap_signal_stop_requested()
		&& !nmap_runtime_is_finished(config))
	{
		if (!nmap_runtime_drain_replies(config, exit_status))
			return (0);
		nmap_runtime_expire_probes(config);
		if (!nmap_runtime_schedule_ready(config, exit_status))
			return (0);
		if (nmap_sender_pool_has_error(config))
		{
			if (exit_status)
				*exit_status = 1;
			return (0);
		}
		if (!nmap_runtime_wait(config, exit_status))
			return (0);
	}
	if (nmap_signal_stop_requested())
	{
		if (exit_status)
			*exit_status = 130;
		return (0);
	}
	return (1);
}

int	nmap_run_single_target(t_nmap_config *config, const char *target,
		int *exit_status)
{
	int	success;

	if (!config || !target || target[0] == '\0')
	{
		if (exit_status)
			*exit_status = 1;
		return (0);
	}
	config->cli.target = target;
	success = 0;
	if (!nmap_prepare_target(config, exit_status))
		goto cleanup;
	if (!nmap_prepare_route(config, exit_status))
		goto cleanup;
	if (!nmap_prepare_send_socket(config, exit_status))
		goto cleanup;
	if (!nmap_prepare_pcap(config, exit_status))
		goto cleanup;
	DEBUG_PCAP(config);
	if (!nmap_prepare_runtime(config, exit_status))
		goto cleanup;
	DEBUG_RUNTIME(config);
	if (!nmap_prepare_sender_pool(config, exit_status))
		goto cleanup;
	if (!run_scan_loop(config, exit_status))
		goto cleanup;
	nmap_stop_sender_pool(config);
	nmap_print_report(config);
	success = 1;

cleanup:
	nmap_cleanup_target_scan(config);
	return (success);
}