/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   parsing.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: eric <eric@student.42.fr>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2026/06/30 08:31:43 by eric              #+#    #+#             */
/*   Updated: 2026/08/03 11:39:38 by eric             ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

static int	check_required_args(t_nmap_config *config)
{
	if (config->cli.help)
		return (1);
	if (config->cli.ip_specified && config->cli.file_specified)
	{
		fprintf(stderr,
			"ft_nmap: --ip and --file are mutually exclusive\n");
		return (0);
	}
	if (!config->cli.ip_specified && !config->cli.file_specified)
	{
		fprintf(stderr,
			"ft_nmap: one of --ip or --file is required\n");
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
