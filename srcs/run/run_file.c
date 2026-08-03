/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   run_file.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: eric <eric@student.42.fr>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2026/08/03 15:17:22 by eric              #+#    #+#             */
/*   Updated: 2026/08/03 15:51:32 by eric             ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

int	nmap_run_target_file(t_nmap_config *config, int *exit_status)
{
	size_t	i;
	int		had_error;

	if (!config)
	{
		if (exit_status)
			*exit_status = 1;
		return (0);
	}
	if (!nmap_prepare_target_file(config, exit_status))
		return (0);
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
		if (!nmap_run_single_target(config,
				config->targets.items[i].hostname, exit_status))
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
	return (1);
}