/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   resolve.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: eric <eric@student.42.fr>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2026/06/24 13:04:12 by eric              #+#    #+#             */
/*   Updated: 2026/08/26 14:18:00 by eric             ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "config.h"

#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>

/**
 * @brief Resolve a target name into one usable IPv4 address.
 *
 * @param target Destination structure to fill.
 * @param hostname IPv4 address or hostname supplied by the user.
 * @param no_dns When non-zero, only numeric IPv4 addresses are accepted.
 *
 * @return 0 on success, -1 on resolution failure.
 */
static int	resolve_host(t_nmap_target *target, const char *hostname)
{
	struct addrinfo				hints;
	struct addrinfo				*res;
	const struct sockaddr_in		*addr;
	int							status;

	if (!target || !hostname || hostname[0] == '\0')
		return (-1);
	memset(target, 0, sizeof(*target));
	memset(&hints, 0, sizeof(hints));
	res = NULL;
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	status = getaddrinfo(hostname, NULL, &hints, &res);
	if (status != 0)
	{
		target->gai_error = status;
		fprintf(stderr, "ft_nmap: %s: %s\n",
			hostname, gai_strerror(status));
		return (-1);
	}
	if (!res || !res->ai_addr
		|| res->ai_family != AF_INET
		|| res->ai_addrlen < (socklen_t)sizeof(struct sockaddr_in))
	{
		target->error = EAFNOSUPPORT;
		fprintf(stderr, "ft_nmap: %s: no usable IPv4 address\n",
			hostname);
		if (res)
			freeaddrinfo(res);
		return (-1);
	}
	addr = (const struct sockaddr_in *)res->ai_addr;
	target->addr = *addr;
	target->addr.sin_port = 0;
	target->addr_len = sizeof(target->addr);
	if (!inet_ntop(AF_INET, &target->addr.sin_addr,
			target->ip, sizeof(target->ip)))
	{
		target->error = errno;
		perror("ft_nmap: inet_ntop");
		freeaddrinfo(res);
		return (-1);
	}
	freeaddrinfo(res);
	return (0);
}

static int	target_is_numeric(const char *target)
{
	struct in_addr	addr;

	if (!target)
		return (0);
	return (inet_pton(AF_INET, target, &addr) == 1);
}

static void	resolve_reverse_dns(t_nmap_target *target)
{
	int	status;

	if (!target)
		return ;
	target->hostname[0] = '\0';
	status = getnameinfo(
			(const struct sockaddr *)&target->addr,
			target->addr_len,
			target->hostname,
			sizeof(target->hostname),
			NULL,
			0,
			NI_NAMEREQD);
	if (status != 0)
		target->hostname[0] = '\0';
}

/**
 * @brief Prepare the resolved IPv4 target from parsed CLI input.
 *
 * @param config Global nmap configuration.
 * @param exit_status Output exit status set on resolution failure.
 *
 * @return 1 on success, 0 on failure.
 */
int	nmap_prepare_target(t_nmap_config *config, int *exit_status)
{
	if (!config || !config->cli.target
		|| config->cli.target[0] == '\0')
	{
		if (exit_status)
			*exit_status = 1;
		return (0);
	}
	if (resolve_host(&config->target, config->cli.target) < 0)
	{
		if (exit_status)
			*exit_status = 1;
		return (0);
	}
	if (!config->cli.no_dns
		&& target_is_numeric(config->cli.target))
		resolve_reverse_dns(&config->target);
	return (1);
}