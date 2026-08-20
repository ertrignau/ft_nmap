/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   pars_timeout.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: eric <eric@student.42.fr>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2026/08/20 14:04:48 by eric              #+#    #+#             */
/*   Updated: 2026/08/20 14:05:02 by eric             ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

int	parse_timeout(t_nmap_config *config, int argc, char **argv, int *i)
{
	int	timeout;

	if (!config || !argv || !i)
		return (0);
	if (*i + 1 >= argc)
	{
		fprintf(stderr, "ft_nmap: missing argument for --timeout\n");
		return (0);
	}
	if (config->cli.timeout_specified)
	{
		fprintf(stderr, "ft_nmap: --timeout specified more than once\n");
		return (0);
	}
	(*i)++;
	if (!nmap_parse_int(argv[*i], &timeout) || timeout <= 0)
	{
		fprintf(stderr, "ft_nmap: invalid timeout value: %s\n",
			argv[*i]);
		return (0);
	}
	config->cli.timeout_ms = timeout;
	config->cli.timeout_specified = 1;
	return (1);
}
