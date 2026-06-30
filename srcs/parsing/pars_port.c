/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   pars_port.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: eric <eric@student.42.fr>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2026/06/30 08:42:33 by eric              #+#    #+#             */
/*   Updated: 2026/06/30 08:43:36 by eric             ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static int	port_exists(t_nmap_config *config, uint16_t port)
{
	size_t	i;

	i = 0;
	while (i < config->scan.port_count)
	{
		if (config->scan.ports[i] == port)
			return (1);
		i++;
	}
	return (0);
}

static int	add_port(t_nmap_config *config, int port)
{
	if (port < 1 || port > 65535)
		return (0);
	if (port_exists(config, (uint16_t)port))
		return (1);
	if (config->scan.port_count >= NMAP_MAX_PORTS)
		return (0);
	config->scan.ports[config->scan.port_count] = (uint16_t)port;
	config->scan.port_count++;
	return (1);
}

static int	parse_single_port(t_nmap_config *config, const char *token)
{
	int	port;

	if (!nmap_parse_int(token, &port))
		return (0);
	return (add_port(config, port));
}

static int	parse_port_range(t_nmap_config *config, const char *token)
{
	char	*dash;
	int		start;
	int		end;
	int		port;

	dash = strchr(token, '-');
	if (!dash || dash == token || dash[1] == '\0')
		return (0);
	*dash = '\0';
	if (!nmap_parse_int(token, &start) || !nmap_parse_int(dash + 1, &end))
		return (0);
	if (start > end)
		return (0);
	port = start;
	while (port <= end)
	{
		if (!add_port(config, port))
			return (0);
		port++;
	}
	return (1);
}

static int	parse_port_token(t_nmap_config *config, char *token)
{
	if (!token || token[0] == '\0')
		return (0);
	if (strchr(token, '-'))
		return (parse_port_range(config, token));
	return (parse_single_port(config, token));
}

int	nmap_parse_ports(t_nmap_config *config, const char *arg)
{
	char	*copy;
	char	*token;
	char	*saveptr;

	if (!config || !arg || arg[0] == '\0')
		return (0);
	config->scan.port_count = 0;
	copy = strdup(arg);
	if (!copy)
		return (0);
	token = strtok_r(copy, ",", &saveptr);
	while (token)
	{
		if (!parse_port_token(config, token))
		{
			free(copy);
			return (0);
		}
		token = strtok_r(NULL, ",", &saveptr);
	}
	free(copy);
	return (config->scan.port_count > 0);
}
