/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   pars_retries.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: eric <eric@student.42.fr>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2026/08/20 14:44:58 by eric              #+#    #+#             */
/*   Updated: 2026/08/20 14:48:02 by eric             ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"
#include <stdio.h>

int	parse_retries(t_nmap_config *config, int argc, char **argv, int *i)
{
	int	retries;

	if (!config || !argv || !i)
		return (0);
	if (*i + 1 >= argc)
	{
		fprintf(stderr, "ft_nmap: missing argument for --retries\n");
		return (0);
	}
	if (config->cli.retries_specified)
	{
		fprintf(stderr, "ft_nmap: --retries specified more than once\n");
		return (0);
	}
	(*i)++;
	if (!nmap_parse_int(argv[*i], &retries))
	{
		fprintf(stderr, "ft_nmap: invalid retries value: %s\n", argv[*i]);
		return (0);
	}
	config->cli.retries = retries;
	config->cli.retries_specified = 1;
	return (1);
}
