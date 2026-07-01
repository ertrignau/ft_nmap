/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   parsing_utils.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: eric <eric@student.42.fr>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2026/06/30 08:32:39 by eric              #+#    #+#             */
/*   Updated: 2026/06/30 08:43:30 by eric             ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

int	parse_flag(t_nmap_config *config, int argc, char **argv, int *i)
{
	if (!strcmp(argv[*i], "--ip"))
		return (parse_ip(&config->cli, argc, argv, i));
	if (!strcmp(argv[*i], "--speedup"))
		return (parse_speedup(config, argc, argv, i));
	if (!strcmp(argv[*i], "--port") || !strcmp(argv[*i], "--ports"))
		return (parse_port(&config->cli, argc, argv, i));
	if (!strcmp(argv[*i], "--scan"))
		return (parse_scan(&config->cli, argc, argv, i));
    else
	    fprintf(stderr, "ft_nmap: unknown flag: %s\n", argv[*i]);
    return (0);
}
