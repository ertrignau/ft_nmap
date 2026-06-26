#ifndef NMAP_CONFIG_H
# define NMAP_CONFIG_H

# include <arpa/inet.h>
# include <netinet/in.h>
# include <pcap/pcap.h>
# include <stdint.h>
# include <stddef.h>

# include "runtime.h"

# define NMAP_MAX_PORTS 1024

typedef enum e_nmap_scan_type
{
	NMAP_SCAN_SYN = 1 << 0,
	NMAP_SCAN_NULL = 1 << 1,
	NMAP_SCAN_FIN = 1 << 2,
	NMAP_SCAN_XMAS = 1 << 3,
	NMAP_SCAN_ACK = 1 << 4,
	NMAP_SCAN_UDP = 1 << 5
}	t_nmap_scan_type;

typedef enum e_nmap_socket_error
{
	NMAP_SOCKET_OK = 0,
	NMAP_SOCKET_RAW,
	NMAP_SOCKET_HDRINCL
}	t_nmap_socket_error;

typedef struct s_nmap_cli
{
	const char	*program_name;
	const char	*target;
	const char	*ports_arg;

	uint32_t	scan_mask;

	int			help;
	int			no_dns;
	int			speedup;

	int			timeout_ms;
	int			max_in_flight;

	int			error;
	int			cli_error;
	const char	*bad_arg;
	int			bad_index;
}	t_nmap_cli;

typedef struct s_nmap_target
{
	struct sockaddr_in	addr;
	socklen_t			addr_len;
	char				ip[INET_ADDRSTRLEN];

	int					error;
	int					gai_error;
}	t_nmap_target;

typedef struct s_nmap_route
{
	char				iface[64];
	struct sockaddr_in	src_addr;
	char				src_ip[INET_ADDRSTRLEN];

	int					error;
}	t_nmap_route;

typedef struct s_nmap_socket
{
	int	error;
	int	send_fd;
}	t_nmap_socket;

typedef struct s_nmap_capture
{
	pcap_t				*handle;
	char				errbuf[PCAP_ERRBUF_SIZE];
	int					fd;
	int					datalink;
	int					error;
}	t_nmap_capture;

typedef struct s_nmap_scan
{
	uint16_t			ports[NMAP_MAX_PORTS];
	size_t				port_count;

	uint32_t			scan_mask;
	uint16_t			src_port_base;

	int					timeout_ms;
	int					max_in_flight;
}	t_nmap_scan;

typedef struct s_nmap_config
{
	t_nmap_cli			cli;
	t_nmap_target		target;
	t_nmap_route		route;
	t_nmap_socket		socket;
	t_nmap_capture		capture;
	t_nmap_scan			scan;
	t_nmap_runtime		runtime;
}	t_nmap_config;

#endif