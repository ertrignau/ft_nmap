/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: eric <eric@student.42.fr>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2026/06/10 15:59:54 by ertrigna          #+#    #+#             */
/*   Updated: 2026/08/03 15:46:45 by eric             ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"
#include "debug/debug.h"

#include <string.h>

static void	print_help(const char *progname)
{
	printf("Usage: %s [OPTIONS]\n", progname);
	printf("\n");
	printf("Options:\n");
	printf("  --help                     Show this help message\n");
	printf("  --ip <host>                Target host (IP or hostname)\n");
	printf("  --file <file>              Read targets from file\n");
	printf("  --ports <list|range>       Ports to scan (default: 1-1024)\n");
	printf("  --scan <types>             SYN,NULL,FIN,XMAS,ACK,UDP\n");
	printf("  --speedup <0-250>          Number of concurrent workers\n");
	printf("  --timeout <ms>             Probe timeout\n");
	printf("  --retries <count>          Number of retries\n");
	printf("  --probes-per-thread <n>    Max outstanding probes per worker\n");
	printf("  --no-dns                   Disable reverse DNS lookups\n");
	printf("  --version                  Enable service version detection\n");
	printf("  --os                       Enable OS detection\n");
	printf("  --open                     Show only open ports\n");
	printf("  --reason                   Show reason for port state\n");
}
	
int	main(int ac, char *av[])
{
	t_nmap_config	config;
	int				exit_status;

	exit_status = 0;
	if (!nmap_init_config(&config, av[0], &exit_status))
		return (exit_status);
	if (!nmap_signal_setup(&exit_status))
		goto cleanup;
	if (!nmap_parse_cli(&config, ac, av, &exit_status))
		goto cleanup;
	if (config.cli.help)
	{
		print_help(config.cli.program_name);
		goto cleanup;
	}
	if (!nmap_prepare_scan_config(&config, &exit_status))
		goto cleanup;
	if (config.cli.file_specified)
	{
		if (!nmap_run_target_file(&config, &exit_status))
			goto cleanup;
	}
	else
	{
		if (!nmap_run_single_target(&config,
				config.cli.target, &exit_status))
			goto cleanup;
	}
	PROF_REPORT();

cleanup:
	nmap_cleanup_config(&config);
	return (exit_status);
}