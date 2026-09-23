/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   pars_bool.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: ertrigna <ertrigna@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2026/08/22 13:49:14 by ertrigna          #+#    #+#             */
/*   Updated: 2026/08/22 13:51:28 by ertrigna         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

int	parse_bool_flag(t_nmap_config *config, const char *flag)
{
	if (!config || !flag)
		return (0);
	if (nmap_streq(flag, "--no-dns"))
		config->cli.no_dns = 1;
	else if (nmap_streq(flag, "--short"))
		config->cli.short_output = 1;
	else if (nmap_streq(flag, "--reason"))
		config->cli.show_reason = 1;
	else if (nmap_streq(flag, "--os"))
		config->cli.os_detection = 1;
	else
	{
		return (0);
	}
	return (1);
}
