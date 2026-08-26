#ifndef CONFIG_H
# define CONFIG_H

# include "runtime.h"

# include <pcap/pcap.h>
# include <pthread.h>
# include <stddef.h>
# include <stdint.h>
# include <stdio.h>
# include <string.h>

# define NMAP_MAX_PORTS 1024
# define NMAP_MAX_THREADS 250
# define NMAP_IFACE_NAME_MAX 64

/**
 * @brief Scan families required by the ft_nmap subject.
 */
typedef enum e_nmap_scan_type
{
	NMAP_SCAN_SYN = 1 << 0,
	NMAP_SCAN_NULL = 1 << 1,
	NMAP_SCAN_FIN = 1 << 2,
	NMAP_SCAN_XMAS = 1 << 3,
	NMAP_SCAN_ACK = 1 << 4,
	NMAP_SCAN_UDP = 1 << 5
}	t_nmap_scan_type;

typedef struct s_nmap_worker	t_nmap_worker;

/**
 * @brief One sender-pool job.
 *
 * @note dispatch_id invalidates stale queued jobs when a logical probe changes
 *       generation (for example after a late reply or retransmission cycle).
 */
typedef struct s_nmap_send_job
{
	t_probe		*probe;
	uint32_t	dispatch_id;
}	t_nmap_send_job;

/**
 * @brief Shared producer/consumer queue for sender threads.
 *
 * @note Workers only build/send packets. They never read pcap, classify a
 *       reply, expire a probe, or choose which probe should be scheduled.
 */
typedef struct s_nmap_sender_pool
{
	t_nmap_worker	*workers;
	int				worker_count;

	t_nmap_send_job	*queue;
	size_t			queue_capacity;
	size_t			queue_head;
	size_t			queue_tail;
	size_t			queue_count;

	pthread_mutex_t	lock;
	pthread_cond_t	cond;
	int				initialized;
	int				stop_requested;
	int				send_error;
}	t_nmap_sender_pool;

/**
 * @brief Raw options explicitly supplied through the command line.
 *
 * @note This structure intentionally remains compatible with the existing
 *       parsing branch. Parsing is not part of this architectural rewrite.
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
 * @brief Owned list of target strings prepared by the unchanged parser layer.
 */
typedef struct s_nmap_targets
{
	char	**items;
	size_t	count;
	size_t	capacity;
}	t_nmap_targets;

/**
 * @brief One currently resolved target.
 */
typedef struct s_nmap_target
{
	const char		*name;
	t_nmap_ip_addr	addr;
	char			ip[NMAP_ADDR_TEXT_MAX];
	int				error;
	int				gai_error;
}	t_nmap_target;

/**
 * @brief Route selected by the kernel for the current target.
 */
typedef struct s_nmap_route
{
	char			iface[NMAP_IFACE_NAME_MAX];
	unsigned int	ifindex;
	t_nmap_ip_addr	src_addr;
	char			src_ip[NMAP_ADDR_TEXT_MAX];
	int				error;
}	t_nmap_route;

/**
 * @brief Raw send socket for the current target family.
 */
typedef struct s_nmap_socket
{
	int			send_fd;
	sa_family_t	family;
	int			error;
}	t_nmap_socket;

/**
 * @brief Pcap state owned by the main thread.
 */
typedef struct s_nmap_capture
{
	pcap_t	*handle;
	char	errbuf[PCAP_ERRBUF_SIZE];
	int		fd;
	int		datalink;
	int		error;
}	t_nmap_capture;

/**
 * @brief Effective immutable scan configuration consumed by the engine.
 *
 * @note window_size is the current global outstanding/queued capacity. It is a
 *       fixed window for now; the architecture deliberately leaves the timing
 *       policy outside workers so adaptive Nmap-like congestion control can be
 *       introduced later without touching packet builders or parsers.
 */
typedef struct s_nmap_scan
{
	uint16_t	ports[NMAP_MAX_PORTS];
	size_t		port_count;
	uint32_t	scan_mask;

	int			thread_count;
	int			retries;
	int			tcp_timeout_ms;
	int			udp_timeout_ms;

	int			window_size;
	int			udp_window_size;
	int			udp_dispatch_gap_ms;

	int			no_dns;
	int			version_detection;
	int			os_detection;
	int			open_only;
	int			show_reason;
}	t_nmap_scan;

/**
 * @brief Complete process state.
 *
 * Parsing/options are global. target/route/socket/capture/runtime/sender_pool
 * are prepared and cleaned for each concrete resolved target.
 */
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
