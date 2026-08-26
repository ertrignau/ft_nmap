/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   pars_file.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: eric <eric@student.42.fr>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2026/08/03 12:02:13 by eric              #+#    #+#             */
/*   Updated: 2026/08/03 12:05:06 by eric             ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

int	parse_file(t_nmap_config *config, int argc, char **argv, int *i)
{
	if (!config || !argv || !i)
		return (0);
	if (*i + 1 >= argc)
	{
		fprintf(stderr, "ft_nmap: missing argument for --file\n");
		return (0);
	}
	if (config->cli.file_specified)
	{
		fprintf(stderr, "ft_nmap: --file specified more than once\n");
		return (0);
	}
	(*i)++;
	if (argv[*i][0] == '\0')
	{
		fprintf(stderr, "ft_nmap: empty file path\n");
		return (0);
	}
	config->cli.target_file = argv[*i];
	config->cli.file_specified = 1;
	return (1);
}
