
#include "ft_nmap.h"
#include "debug/debug.h"

/**
 * @brief Execute the main event loop for the current resolved target.
 *
 * @note The main thread owns receive/match/classify/expire/schedule/wait.
 *       Sender workers only execute generations selected by the scheduler.
 */
static int	run_scan_loop(t_nmap_config *config, int *exit_status)
{
	while (!nmap_signal_stop_requested()
		&& !nmap_runtime_is_finished(config))
	{
		/* Consume replies before expiration to favor packets arriving on time. */
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
	/* A last worker may fail while simultaneously completing the final probe. */
	if (nmap_sender_pool_has_error(config))
	{
		if (exit_status)
			*exit_status = 1;
		return (0);
	}
	return (1);
}

/**
 * @brief Prepare, scan, report and clean one target.
 */
static int	run_target(t_nmap_config *config, const char *target,
		int *exit_status)
{
	int	success;

	success = 0;
	if (!nmap_prepare_target(config, target, exit_status)
		|| !nmap_prepare_route(config, exit_status)
		|| !nmap_prepare_send_socket(config, exit_status)
		|| !nmap_prepare_pcap(config, exit_status)
		|| !nmap_prepare_runtime(config, exit_status)
		|| !nmap_prepare_sender_pool(config, exit_status))
		goto cleanup;
	DEBUG_DEV_CONFIG(config);
	DEBUG_SOCKET(config);
	DEBUG_PCAP(config);
	DEBUG_RUNTIME(config);
	if (!run_scan_loop(config, exit_status))
		goto cleanup;
	/* Workers must be joined before report/cleanup can inspect/free probes. */
	nmap_stop_sender_pool(config);
	nmap_print_report(config);
	success = 1;
cleanup:
	nmap_cleanup_current_target(config);
	return (success);
}

/**
 * @brief Scan every prepared target and continue after target-local failures.
 */
int	nmap_run(t_nmap_config *config, int *exit_status)
{
	size_t	i;
	int		had_error;

	if (!config)
	{
		if (exit_status)
			*exit_status = 1;
		return (0);
	}
	i = 0;
	had_error = 0;
	while (i < config->targets.count)
	{
		if (nmap_signal_stop_requested())
		{
			if (exit_status)
				*exit_status = 130;
			return (0);
		}
		if (!run_target(config, config->targets.items[i], exit_status))
		{
			if (exit_status && *exit_status == 130)
				return (0);
			had_error = 1;
			if (exit_status)
				*exit_status = 0;
		}
		i++;
	}
	if (had_error && exit_status)
		*exit_status = 1;
	return (!had_error);
}
