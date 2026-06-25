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

#include "nmap.h"

int	create_raw_socket(int protocol)
{
	int	sock;
	int	on;

	sock = socket(AF_INET, SOCK_RAW, protocol);
	if (sock < 0)
	{
		fprintf(stderr, "You must have sudo permission\n");
		exit (1);
	}
	if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP)
	{
		if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
		{
			close(sock);
			return (-1);
		}
	}
	return (sock);	
}

int	init_socket(t_scan *scan)
{
	scan->socket.tcp = create_raw_socket(IPPROTO_TCP);
	if (scan->socket.tcp < 0)
		return (-1);
	scan->socket.udp = create_raw_socket(IPPROTO_UDP);
	if (scan->socket.udp < 0)
		return (-1);
	scan->socket.icmp = create_raw_socket(IPPROTO_ICMP);
	if (scan->socket.icmp < 0)
		return (-1);
	return (0);
}

void	close_socket(t_scan *scan)
{
	if (scan->socket.tcp >= 0)
		close(scan->socket.tcp);
	if (scan->socket.udp >= 0)
		close(scan->socket.udp);
	if (scan->socket.icmp >= 0)
		close(scan->socket.icmp);
}
