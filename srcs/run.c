#include "ft_nmap.h"
#include "debug/debug.h"

#include <time.h>

/** Return a monotonic timestamp used only for elapsed-time reporting. */
static uint64_t	run_now_ms(void)
{
	struct timespec	ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return (0);
	return ((uint64_t)ts.tv_sec * 1000ULL
		+ (uint64_t)ts.tv_nsec / 1000000ULL);
}

/** Safely subtract two monotonic timestamps. */
static uint64_t	elapsed_ms(uint64_t start, uint64_t end)
{
	if (end < start)
		return (0);
	return (end - start);
}

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
	uint64_t	start_ms;
	uint64_t	end_ms;
	int			success;

	start_ms = run_now_ms();
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

	/*
	 * Freeze all runtime state before the read-only output module consumes it.
	 */
	nmap_stop_sender_pool(config);

	end_ms = run_now_ms();
	nmap_output_print_target_report(config,
		elapsed_ms(start_ms, end_ms),
		config->targets.count > 1);
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
	uint64_t	start_ms;
	uint64_t	end_ms;
	size_t		i;
	size_t		completed;
	int			had_error;

	if (!config)
	{
		if (exit_status)
			*exit_status = 1;
		return (0);
	}
	start_ms = run_now_ms();
	i = 0;
	completed = 0;
	had_error = 0;
	while (i < config->targets.count)
	{
		if (nmap_signal_stop_requested())
		{
			if (exit_status)
				*exit_status = 130;
			return (0);
		}
		if (run_target(config,
				config->targets.items[i], exit_status))
			completed++;
		else
		{
			if (exit_status && *exit_status == 130)
				return (0);
			had_error = 1;
			if (exit_status)
				*exit_status = 0;
		}
		i++;
	}
	end_ms = run_now_ms();

	nmap_output_print_run_summary(
		config->targets.count,
		completed,
		elapsed_ms(start_ms, end_ms));

	if (had_error && exit_status)
		*exit_status = 1;
	return (!had_error);
}