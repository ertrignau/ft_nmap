/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   nmap.h                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: ertrigna <ertrigna@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2026/06/10 15:45:51 by ertrigna          #+#    #+#             */
/*   Updated: 2026/06/23 15:57:30 by ertrigna         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef NMAP_H
#define NMAP_H

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/time.h>
#include <time.h>
#include <pthread.h>
#include <pcap.h>

#define MAX_PORT 1024
#define DEFAULT_TIMEOUT_SEC 1

typedef enum e_scan_type
{
	SCAN_SYN,
	SCAN_NULL,
	SCAN_ACK,
	SCAN_XMAS,
	SCAN_FIN,
	SCAN_UDP,
	
} t_scan_type;

typedef enum e_port_state
{
	PORT_UNKNOW,
	PORT_OPEN,
	PORT_CLOSED,
	PORT_FILTERED,
	PORT_UNFILTERED,
	PORT_OPEN_FILTERED,
} t_port_state;

typedef struct s_socket
{
	int					tcp;
	int					udp;
	int					icmp;
} t_socket;

typedef struct s_target
{
	char				*hostname;
	char				ip[INET_ADDRSTRLEN];
	struct sockaddr_in	addr;
} t_target;

typedef struct s_pcap
{
	pcap_t	*handle;
	char	errbuf[PCAP_ERRBUF_SIZE];
}	t_pcap;

typedef struct s_port_result
{
	int					port;
	t_scan_type			scan_type;
	t_port_state		port_state;
} t_port_result;

typedef struct s_scan
{
	t_target			target;
	t_pcap				pcap;
	int					port[MAX_PORT];
	int					port_count;
	int					timeout_sec;
	t_port_result		results[MAX_PORT];
} t_scan;

/*INIT*/

/*SOCKET*/

/*SCANNER*/

#endif