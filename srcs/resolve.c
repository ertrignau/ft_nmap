/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   resolve.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: eric <eric@student.42.fr>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2026/06/24 13:04:12 by eric              #+#    #+#             */
/*   Updated: 2026/06/24 16:48:47 by eric             ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "nmap.h"

int	resolve_host(t_target *target)
{
	struct addrinfo		hints;
	struct addrinfo		*res;
	struct sockaddr_in	*addr;

	if (!target || !target->hostname)
		return (-1);
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_RAW;
	
	if (getaddrinfo(target->hostname, NULL, &hints, &res) != 0)
		return (-1);
	addr = (struct sockaddr_in *)res->ai_addr;
	memcpy(&target->addr, addr, sizeof(struct sockaddr_in));

	if (!inet_ntop(AF_INET, &addr->sin_addr, target->ip, sizeof(target->ip)))
	{
		freeaddrinfo(res);
		return (-1);
	}
	freeaddrinfo(res);
	return (0);
}	
