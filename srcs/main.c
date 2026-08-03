/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: eric <eric@student.42.fr>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2026/06/10 15:59:54 by ertrigna          #+#    #+#             */
/*   Updated: 2026/08/03 11:58:13 by eric             ###   ########.fr       */
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
	// initialisation de la configuration globale
	if (!nmap_init_config(&config, av[0], &exit_status))
		return (exit_status);

	// preparation du handler de signal
	if (!nmap_signal_setup(&exit_status))
		return (exit_status);

	// parsing des arguments
	if (!nmap_parse_cli(&config, ac, av, &exit_status))
		goto cleanup;
	
	// print --help
	if (config.cli.help)
	{
		print_help(config.cli.program_name);
		goto cleanup;
	}

	// transformation des options CLI en configuration de scan
	if (!nmap_prepare_scan_config(&config, &exit_status))
		goto cleanup;

	// resolution du nom ou de l'adresse de la cible
	if (!nmap_prepare_target(&config, &exit_status))
		goto cleanup;

	// resolution de l'interface et de l'adresse IP source
	if (!nmap_prepare_route(&config, &exit_status))
		goto cleanup;

	//ouverture de la raw socket d'envoi
	if (!nmap_prepare_send_socket(&config, &exit_status))
		goto cleanup;

	//mise en place de pcap AVANT le premier send
	if (!nmap_prepare_pcap(&config, &exit_status))
		goto cleanup;
	DEBUG_PCAP(&config);

	//initialisation des structures runtime
	if (!nmap_prepare_runtime(&config, &exit_status))
		goto cleanup;
	DEBUG_RUNTIME(&config);

	//initialisation des workers d'envoi
	if (!nmap_prepare_sender_pool(&config, &exit_status))
		goto cleanup;

	//boucle principale
	while (!nmap_signal_stop_requested()
		&& !nmap_runtime_is_finished(&config))
	{
		//lire les reponses deja disponibles via pcap
		if (!nmap_runtime_drain_replies(&config, &exit_status))
			break;

		//marquer les probes expirees
		nmap_runtime_expire_probes(&config);

		//envoyer les probes autorisees par le scheduler
		if (!nmap_runtime_schedule_ready(&config, &exit_status))
			break;

		if (nmap_sender_pool_has_error(&config))
		{
			exit_status = 1;
			break ;
		}

		//attendre le prochain evenement utile
		if (!nmap_runtime_wait(&config, &exit_status))
			break;
	}

	if (nmap_signal_stop_requested())
		exit_status = 130;

	/*
	 * Les workers peuvent encore posséder une probe QUEUED ou être en train
	 * de terminer un sendto(). On les stop/join avant d'imprimer le report
	 * pour éviter de lire des probes pendant qu'un thread les modifie.
	 */
	nmap_stop_sender_pool(&config);

	nmap_print_report(&config);
	PROF_REPORT();

cleanup:
	//free toutes les ressources et close les sockets / pcap
	nmap_cleanup_config(&config);
	return (exit_status);
}