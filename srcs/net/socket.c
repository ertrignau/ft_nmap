/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   socket.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: eric <eric@student.42.fr>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2026/06/10 15:59:39 by ertrigna          #+#    #+#             */
/*   Updated: 2026/06/24 12:03:15 by eric             ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "config.h"

#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>

int	nmap_prepare_send_socket(t_nmap_config *config, int *exit_status)
{
	int	on;

	if (!config)
	{
		if (exit_status)
			*exit_status = 1;
		return (0);
	}
	config->socket.send_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (config->socket.send_fd < 0)
	{
		perror("ft_nmap: socket");
		if (exit_status)
			*exit_status = 1;
		return (0);
	}
	on = 1;
	if (setsockopt(config->socket.send_fd, IPPROTO_IP,
			IP_HDRINCL, &on, sizeof(on)) < 0)
	{
		perror("ft_nmap: setsockopt(IP_HDRINCL)");
		close(config->socket.send_fd);
		config->socket.send_fd = -1;
		if (exit_status)
			*exit_status = 1;
		return (0);
	}
	return (1);
}