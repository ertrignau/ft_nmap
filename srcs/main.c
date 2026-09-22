#include "ft_nmap.h"
#include "debug/debug.h"

#include <stdio.h>

/** Print the command-line options supported by the current parser. */
static void	print_help(const char *progname)
{
	printf("Usage: %s [OPTIONS]\n\n", progname);
	printf("Options:\n");
	printf("  --help                     Show this help message\n");
	printf("  --ip <host>                Target host (IP or hostname)\n");
	printf("  --file <file>              Read targets from file\n");
	printf("  --ports <list|range>       Ports to scan (default: 1-1024)\n");
	printf("  --scan <types>             SYN,NULL,FIN,XMAS,ACK,UDP\n");
	printf("  --speedup <0-250>          Additional sender threads\n");
	printf("  --timeout <ms>             Override TCP/UDP probe timeout\n");
	printf("  --retries <count>          Maximum retransmissions\n");
	printf("  --ttl <0-255>             Set IPv4 TTL / IPv6 Hop Limit\n");
	printf("  --no-dns                   Disable reverse DNS lookups\n");
	printf("  --os                       Enable OS detection\n");
	printf("  --open                     Show only open/open|filtered ports\n");
	printf("  --reason                   Show the reason for each state\n");
}

/**
 * @brief Program entry point.
 *
 * @note High-level orchestration intentionally fits in main.c + run.c so the
 *       complete control flow remains easy to explain during correction.
 */
int	main(int ac, char **av)
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
	if (!nmap_prepare_targets(&config, &exit_status))
		goto cleanup;
	nmap_run(&config, &exit_status);
	PROF_REPORT();
cleanup:
	nmap_cleanup_config(&config);
	return (exit_status);
}
