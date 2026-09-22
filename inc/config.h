
#ifndef CONFIG_H
# define CONFIG_H

# include "runtime.h"

# include <pcap/pcap.h>
# include <pthread.h>
# include <stddef.h>
# include <stdint.h>

# define NMAP_MAX_PORTS 1024
# define NMAP_MAX_TARGETS 1024
# define NMAP_TARGET_INITIAL_CAPACITY 16
# define NMAP_MAX_THREADS 250
# define NMAP_IFACE_NAME_MAX 64
# define NMAP_HOSTNAME_MAX 256

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
 * @brief One immutable sender-pool job.
 *
 * @note dispatch_id identifies the exact scheduling generation. A job that is
 *       still waiting in the queue becomes stale as soon as the logical probe
 *       is completed or reserved again with another generation.
 */
typedef struct s_nmap_send_job
{
	t_probe		*probe;
	uint32_t	dispatch_id;
}	t_nmap_send_job;

/**
 * @brief Shared producer/consumer queue for sender threads.
 *
 * Workers only execute an already selected send generation. They never read
 * pcap, classify replies, expire probes, decide retries, or choose scheduling
 * policy. Runtime state changes made by workers are limited to the atomic
 * begin/commit/fail bookkeeping surrounding the actual send syscall.
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
 * @note The parser records user intent here. Runtime/network policy is
 *       normalized later by nmap_prepare_scan_config().
 */
typedef struct s_nmap_cli
{
	const char	*program_name;
	const char	*target;
	const char	*target_file;

	uint32_t	scan_mask;

	int			help;
	int			no_dns;
	int			os_detection;
	int			open_only;
	int			show_reason;

	int			speedup;
	int			retries;
	int			timeout_ms;
	int			ttl;

	int			ip_specified;
	int			file_specified;
	int			ports_specified;
	int			scan_specified;
	int			speedup_specified;
	int			retries_specified;
	int			timeout_specified;
	int			ttl_specified;
}	t_nmap_cli;

/**
 * @brief Owned list of target strings prepared from --ip or --file.
 */
typedef struct s_nmap_targets
{
	char	**items;
	size_t	count;
	size_t	capacity;
}	t_nmap_targets;

/**
 * @brief One currently resolved target.
 *
 * addr is the semantic source of truth. ip is only its cached presentation
 * form for diagnostics, reports and pcap filter construction.
 */
typedef struct s_nmap_target
{
	const char		*name;
	t_nmap_ip_addr	addr;
	char			ip[NMAP_ADDR_TEXT_MAX];
	char			hostname[NMAP_HOSTNAME_MAX];

	/*
	 * Lightweight OS fingerprint.
	 *
	 * observed_hop_limit is the IPv4 TTL or IPv6 Hop Limit received from
	 * the target itself. initial_hop_limit is the nearest conventional
	 * initial value inferred from that observation: 64, 128 or 255.
	 */
	uint8_t			observed_hop_limit;
	uint8_t			initial_hop_limit;
}	t_nmap_target;

/**
 * @brief Route selected by the kernel for the current target.
 *
 * src_addr is the semantic source of truth. src_ip is a cached presentation
 * string. ifindex is also the IPv6 zone when a scoped route is required.
 */
typedef struct s_nmap_route
{
	char			iface[NMAP_IFACE_NAME_MAX];
	unsigned int	ifindex;
	t_nmap_ip_addr	src_addr;
	char			src_ip[NMAP_ADDR_TEXT_MAX];
}	t_nmap_route;

/**
 * @brief Raw send socket for the current target family.
 */
typedef struct s_nmap_socket
{
	int			send_fd;
	sa_family_t	family;
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
}	t_nmap_capture;

/**
 * @brief Effective scan configuration consumed by the engine.
 *
 * @note With --speedup 0, window_size/UDP pacing belong to the adaptive core.
 *       With --speedup N, those limits are intentionally ignored: N workers,
 *       each with at most one outstanding probe, define concurrency directly.
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
	int			ttl;

	int			window_size;
	int			udp_window_size;
	int			udp_send_gap_ms;

	int			no_dns;
	int			os_detection;
	int			open_only;
	int			show_reason;
}	t_nmap_scan;

/**
 * @brief Complete process state.
 *
 * Parsing/options and the target list are process-scoped. target/route/socket/
 * capture/runtime/sender_pool are prepared and cleaned for each resolved
 * target.
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
