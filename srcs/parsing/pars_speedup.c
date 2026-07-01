/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   pars_speedup.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: eric <eric@student.42.fr>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2026/06/30 08:31:43 by eric              #+#    #+#             */
/*   Updated: 2026/06/30 08:32:34 by eric             ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

int	parse_speedup(t_nmap_config *cli, int argc, char **argv, int *i)
{
    int speedup;

    if (*i + 1 >= argc)
    {
        fprintf(stderr, "ft_nmap: missing argument for --speedup\n");
        return (0);
    }
    (*i)++;
    speedup = atoi(argv[*i]);
    if (!is_number(argv[*i]))
	{
		fprintf(stderr, "ft_nmap: invalid value must be numeric only: %s\n", argv[*i]);
		return (0);
	}
    if (speedup < 1 || speedup > 250)
    {
        fprintf(stderr, "ft_nmap: invalid speedup value: %s\n", argv[*i]);
        return (0);
    }
    cli->speedup = speedup;
    return (1);
}
