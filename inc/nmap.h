/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   nmap.h                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: eric <eric@student.42.fr>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2026/06/10 15:45:51 by ertrigna          #+#    #+#             */
/*   Updated: 2026/06/24 17:02:09 by eric             ###   ########.fr       */
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
#include <netinet/ip_icmp.h>
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
	PORT_UNKNOWN,
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
	t_socket			socket;
	int					port[MAX_PORT];
	int					port_count;
	int					timeout_sec;
	t_port_result		results[MAX_PORT];
} t_scan;

/*INIT*/
void	init_scan(t_scan *scan);
void	init_target(t_target *target);
void	init_socket_structure(t_socket *socket);

/*SOCKET*/
int		create_raw_socket(int protocol);
int		init_socket(t_scan *scan);
void	close_socket(t_scan *scan);

/*RESOLVE DNS*/
int		resolve_host(t_target *target);

/*PACKET*/
void	build_tcp_packet(struct tcphdr *tcp, uint16_t src_port, uint16_t dst_port, t_scan_type type);
/*SCANNER*/

#endif