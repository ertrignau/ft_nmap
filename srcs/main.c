/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: eric <eric@student.42.fr>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2026/06/10 15:59:54 by ertrigna          #+#    #+#             */
/*   Updated: 2026/06/24 16:49:15 by eric             ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "nmap.h"

// static void	print_usage()
// {
// 	printf("./ft_nmap: [Options]\n");
// 	printf("-help Print this help screen\n");
// 	printf("--ports ports to scan (eg: 1-10 or 1,2,3 or 1,5-15)\n");
// 	printf("-ip ip addresses to scan in dot format\n");
// 	printf("--file File name containing IP addresses to scan,\n");
// 	printf("--speedup [250 max] number of parallel threads to use\n")
// 	printf("--scan SYN/NULL/FIN/XMAS/ACK/UDP\n")
// }

int	main(int ac, char **av)
{
	t_scan	scan;

	if (ac != 2)
		return (printf("Usage: %s <host>\n", av[0]), 1);

	init_scan(&scan);
	scan.target.hostname = strdup(av[1]);
	if (!scan.target.hostname)
		return (1);

	if (resolve_host(&scan.target) < 0)
	{
		printf("resolve_host failed\n");
		free(scan.target.hostname);
		return (1);
	}

	printf("hostname : %s\n", scan.target.hostname);
	printf("ip       : %s\n", scan.target.ip);

	free(scan.target.hostname);
	return (0);
}
