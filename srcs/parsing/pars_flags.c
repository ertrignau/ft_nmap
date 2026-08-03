/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   pars_flags.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: eric <eric@student.42.fr>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2026/06/30 08:32:39 by eric              #+#    #+#             */
/*   Updated: 2026/08/03 12:07:00 by eric             ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

int	parse_flag(t_nmap_config *config, int argc, char **argv, int *i)
{
	if (nmap_streq(argv[*i], "--help"))
	{
		config->cli.help = 1;
		return (1);
	}
	if (nmap_streq(argv[*i], "--ip"))
		return (parse_ip(config, argc, argv, i));
	if (nmap_streq(argv[*i], "--speedup"))
		return (parse_speedup(config, argc, argv, i));
	if (nmap_streq(argv[*i], "--port") || nmap_streq(argv[*i], "--ports"))
		return (parse_port(config, argc, argv, i));
	if (nmap_streq(argv[*i], "--file"))
		return (parse_file(config, argc, argv, i));
	if (nmap_streq(argv[*i], "--scan"))
		return (parse_scan(config, argc, argv, i));
	fprintf(stderr, "ft_nmap: unknown flag: %s\n", argv[*i]);
	return (0);
}
