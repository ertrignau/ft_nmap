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

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef IPV6_HDRINCL
# define IPV6_HDRINCL 36
#endif

/**
 * @brief Open an IPv4 raw socket accepting a complete user-built IP header.
 */
static int	prepare_ipv4_socket(t_nmap_socket *sock)
{
	int	on;

	sock->send_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (sock->send_fd < 0)
		return (0);
	on = 1;
	if (setsockopt(sock->send_fd, IPPROTO_IP,
			IP_HDRINCL, &on, sizeof(on)) < 0)
		return (0);
	sock->family = AF_INET;
	return (1);
}

/**
 * @brief Open an IPv6 raw socket accepting a complete user-built IPv6 header.
 */
static int	prepare_ipv6_socket(t_nmap_socket *sock)
{
	int	on;

	sock->send_fd = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);
	if (sock->send_fd < 0)
		return (0);
	on = 1;
	if (setsockopt(sock->send_fd, IPPROTO_IPV6,
			IPV6_HDRINCL, &on, sizeof(on)) < 0)
		return (0);
	sock->family = AF_INET6;
	return (1);
}

/**
 * @brief Prepare the family-specific raw socket for the current target.
 *
 * @note Socket lifetime is target-scoped because a target list may contain a
 *       mix of IPv4 and IPv6 destinations.
 */
int	nmap_prepare_send_socket(t_nmap_config *config, int *exit_status)
{
	int	ok;
	int	saved_error;

	if (!config)
	{
		if (exit_status)
			*exit_status = 1;
		return (0);
	}
	memset(&config->socket, 0, sizeof(config->socket));
	config->socket.send_fd = -1;
	if (config->target.addr.family == AF_INET)
		ok = prepare_ipv4_socket(&config->socket);
	else if (config->target.addr.family == AF_INET6)
		ok = prepare_ipv6_socket(&config->socket);
	else
	{
		errno = EAFNOSUPPORT;
		ok = 0;
	}
	if (!ok)
	{
		saved_error = errno;
		if (config->socket.send_fd >= 0)
			close(config->socket.send_fd);
		config->socket.send_fd = -1;
		config->socket.error = saved_error;
		fprintf(stderr, "ft_nmap: raw socket: %s\n",
			strerror(saved_error));
		if (exit_status)
			*exit_status = 1;
		return (0);
	}
	return (1);
}
