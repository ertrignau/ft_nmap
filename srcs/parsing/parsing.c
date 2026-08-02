/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   parsing.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: eric <eric@student.42.fr>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2026/06/30 08:31:43 by eric              #+#    #+#             */
/*   Updated: 2026/07/27 14:50:26 by eric             ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

static int	check_required_args(t_nmap_config *config)
{
	if (!config->cli.target)
	{
		fprintf(stderr, "ft_nmap: missing --ip\n");
		return (0);
	}
	if (config->scan.port_count == 0)
	{
		fprintf(stderr, "ft_nmap: missing --ports\n");
		return (0);
	}
	return (1);
}

int	nmap_parse_cli(t_nmap_config *config, int argc, char **argv, int *exit_status)
{
	int i;

	if (!config)
	{
		if (exit_status)
			*exit_status = 1;
		return (0);
	}

	i = 1;
	while (i < argc)
	{
		if (!parse_flag(config, argc, argv, &i))
		{
			if (exit_status)
				*exit_status = 1;
			return (0);
		}
		i++;
	}
	if (!check_required_args(config))
	{
		if (exit_status)
			*exit_status = 1;
		return (0);
	}
	return (1);
}
