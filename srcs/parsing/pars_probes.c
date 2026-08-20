/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   pars_probes.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: eric <eric@student.42.fr>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2026/08/20 14:20:07 by eric              #+#    #+#             */
/*   Updated: 2026/08/20 14:45:02 by eric             ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

int	parse_probes_per_thread(t_nmap_config *config,
		int argc, char **argv, int *i)
{
	int	value;

	if (!config || !argv || !i)
		return (0);
	if (*i + 1 >= argc)
	{
		fprintf(stderr,
			"ft_nmap: missing argument for --probes-per-thread\n");
		return (0);
	}
	if (config->cli.probes_per_thread_specified)
	{
		fprintf(stderr,
			"ft_nmap: --probes-per-thread specified more than once\n");
		return (0);
	}
	(*i)++;
	if (!nmap_parse_int(argv[*i], &value) || value <= 0)
	{
		fprintf(stderr,
			"ft_nmap: invalid probes-per-thread value: %s\n",
			argv[*i]);
		return (0);
	}
	config->cli.probes_per_thread = value;
	config->cli.probes_per_thread_specified = 1;
	return (1);
}
