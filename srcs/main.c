/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: eric <eric@student.42.fr>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2026/06/10 15:59:54 by ertrigna          #+#    #+#             */
/*   Updated: 2026/06/24 16:49:15 by eric             ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"
#include "debug/debug.h"

#include <string.h>

int	main(void)
{
	t_nmap_config	config;
	int				exit_status;

	exit_status = 0;
	memset(&config, 0, sizeof(config));

	//preparation du handler de signal
	if (!nmap_signal_setup(&exit_status))
		return (exit_status);

	//parsing des arguments
	//TODO : UNCOMMENT : quand le parsing sera prêt
	// if (!nmap_parse_cli(&config, &exit_status))
	// 	return (exit_status);
	// DEBUG_PARSING(&config);

	//preparation de la cible
	//TODO : UNCOMMENT : quand le resolve sera prêt
	// if (!nmap_prepare_target(&config, &exit_status))
	// 	return (exit_status);
	// DEBUG_TARGET(&config);

	//preparation de l'interface et de l'IP source
	//TODO : UNCOMMENT : quand la detection de route sera prête
	// if (!nmap_prepare_route(&config, &exit_status))
	// 	return (exit_status);
	// DEBUG_ROUTE(&config);

	//TODO : DELETE : bypass temporaire du parsing + resolve + route
	if (!nmap_load_hardcoded_dev_config(&config))
		return (1);
	DEBUG_DEV_CONFIG(&config);

	//ouverture de la raw socket d'envoi
	if (!nmap_prepare_send_socket(&config, &exit_status))
		goto cleanup;
	DEBUG_SOCKET(&config);

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