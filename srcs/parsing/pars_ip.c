/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   pars_ip.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: eric <eric@student.42.fr>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2026/07/27 11:16:00 by eric              #+#    #+#             */
/*   Updated: 2026/07/27 11:25:42 by eric             ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

int	parse_ip(t_nmap_config *config, int argc, char **argv, int *i)
{
	if (!config || !argv || !i)
		return (0);
	if (*i + 1 >= argc)
	{
		fprintf(stderr, "ft_nmap: missing argument for --ip\n");
		return (0);
	}
	if (config->cli.target)
	{
		fprintf(stderr, "ft_nmap: --ip specified more than once\n");
		return (0);
	}
	(*i)++;
	if (argv[*i][0] == '\0')
	{
		fprintf(stderr, "ft_nmap: empty target\n");
		return (0);
	}
	config->cli.target = argv[*i];
	return (1);
}
