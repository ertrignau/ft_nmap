/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   resolve.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: eric <eric@student.42.fr>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2026/06/24 13:04:12 by eric              #+#    #+#             */
/*   Updated: 2026/07/27 15:07:56 by eric             ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"
#include "errno.h"

static int	resolve_host(t_nmap_target *target, const char *hostname)
{
	struct addrinfo		hints;
	struct addrinfo		*res;
	struct sockaddr_in	*addr;
	int					status;

	if (!target || !hostname)
		return (-1);
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_RAW;

	status = getaddrinfo(hostname, NULL, &hints, &res);
	if (status != 0)
	{
		target->gai_error = status;
		fprintf(stderr, "ft_nmap: %s: %s\n",
			hostname, gai_strerror(status));
		return (-1);
	}
	if (!res || !res->ai_addr)
	{
		freeaddrinfo(res);
		return (-1);
	}

	addr = (struct sockaddr_in *)res->ai_addr;
	memcpy(&target->addr, addr, sizeof(struct sockaddr_in));
	target->addr_len = sizeof(struct sockaddr_in);

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

int	nmap_prepare_target(t_nmap_config *config, int *exit_status)
{
	if (!config || !config->cli.target)
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
	return (1);
}
