/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   init.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: eric <eric@student.42.fr>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2026/06/23 15:49:41 by ertrigna          #+#    #+#             */
/*   Updated: 2026/06/24 16:40:39 by eric             ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "nmap.h"

void	init_socket_structure(t_socket *socket)
{
	if (!socket)
		return ;
	socket->tcp		= -1;
	socket->udp		= -1;
	socket->icmp	= -1;
}

void	init_target(t_target *target)
{
	if (!target)
		return;
	memset(target, 0, sizeof(t_target));
	target->hostname = NULL;
	target->addr.sin_family = AF_INET;
}

void	init_scan(t_scan *scan)
{
	if (!scan)
		return;
	memset(scan, 0, sizeof(t_scan));
	init_socket_structure(&scan->socket);
	init_target(&scan->target);
	scan->pcap.handle = NULL;
	memset(scan->pcap.errbuf, 0, PCAP_ERRBUF_SIZE);
	scan->port_count = 0;
	scan->timeout_sec = DEFAULT_TIMEOUT_SEC;
}
