/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   pars_speedup.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: eric <eric@student.42.fr>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2026/06/30 08:31:43 by eric              #+#    #+#             */
/*   Updated: 2026/08/03 15:58:20 by eric             ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

int	parse_speedup(t_nmap_config *config, int argc, char **argv, int *i)
{
	int	speedup;

	if (!config || !argv || !i)
		return (0);
	if (*i + 1 >= argc)
	{
		fprintf(stderr, "ft_nmap: missing argument for --speedup\n");
		return (0);
	}
	if (config->cli.speedup_specified)
	{
		fprintf(stderr, "ft_nmap: --speedup specified more than once\n");
		return (0);
	}
	(*i)++;
	if (!nmap_parse_int(argv[*i], &speedup)
		|| speedup < 0
		|| speedup > 250)
	{
		fprintf(stderr, "ft_nmap: invalid speedup value: %s\n",
			argv[*i]);
		return (0);
	}
	config->cli.speedup = speedup;
	config->cli.speedup_specified = 1;
	return (1);
}