
#ifndef CONFIG_H
# define CONFIG_H

# include <arpa/inet.h>
# include <netinet/in.h>
# include <pcap/pcap.h>
# include <pthread.h>
# include <stddef.h>
# include <stdint.h>
# include <stdio.h>
# include <string.h>

# include "runtime.h"

# define NMAP_MAX_PORTS 1024
# define NMAP_MAX_THREADS 250

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

typedef struct s_nmap_worker		t_nmap_worker;

/**
 * @brief Sender pool state.
 *
 * @note The main thread still owns pcap, classification and expiration. Workers
 *       only build and send packets.
 */
typedef struct s_nmap_sender_pool
{
	t_nmap_worker	*workers;
	int				worker_count;

	pthread_mutex_t	runtime_lock;
	int				initialized;
	int				stop_requested;
	int				send_error;
}	t_nmap_sender_pool;

/**
 * @brief Raw options explicitly supplied through the command line.
 *
 * @note Zero-valued fields mean that the option was not supplied, except when
 *       the matching *_specified field is set.
 */
typedef struct s_nmap_cli
{
	const char	*program_name;
	const char	*target;
	const char	*target_file;
	const char	*ports_arg;

	uint32_t	scan_mask;

	int			help;
	int			scan_specified;

	int			speedup;
	int			speedup_specified;

	int			retries;
	int			retries_specified;

	int			timeout_ms;
	int			timeout_specified;

	int			probes_per_thread;
	int			probes_per_thread_specified;

	int			no_dns;
	int			version_detection;
	int			os_detection;
	int			open_only;
	int			show_reason;
}	t_nmap_cli;

/**
 * @brief Owned list of targets prepared after parsing.
 */
typedef struct s_nmap_targets
{
	char	**items;
	size_t	count;
	size_t	capacity;
}	t_nmap_targets;

typedef struct s_nmap_target
{
	const char			*name;
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
	pcap_t	*handle;
	char	errbuf[PCAP_ERRBUF_SIZE];
	int		fd;
	int		datalink;
	int		error;
}	t_nmap_capture;

/**
 * @brief Effective scan configuration consumed by the engine.
 *
 * @note The runtime, scheduler and workers must read this structure instead of
 *       config.cli.
 */
typedef struct s_nmap_scan
{
	uint16_t	ports[NMAP_MAX_PORTS];
	size_t		port_count;

	uint32_t	scan_mask;
	uint16_t	src_port_base;

	int			thread_count;
	int			retries;

	int			tcp_timeout_ms;
	int			udp_timeout_ms;

	int			max_outstanding_per_sender;
	int			max_in_flight;
	int			udp_max_in_flight;

	int			tcp_send_gap_ms;
	int			udp_dispatch_gap_ms;

	int			no_dns;
	int			version_detection;
	int			os_detection;
	int			open_only;
	int			show_reason;
}	t_nmap_scan;

typedef struct s_nmap_config
{
	t_nmap_cli			cli;
	t_nmap_targets		targets;
	t_nmap_target		target;
	t_nmap_route		route;
	t_nmap_socket		socket;
	t_nmap_capture		capture;
	t_nmap_scan			scan;
	t_nmap_runtime		runtime;
	t_nmap_sender_pool	sender_pool;
}	t_nmap_config;

#endif
