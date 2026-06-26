#ifndef NMAP_RUNTIME_H
# define NMAP_RUNTIME_H

# include <stdint.h>
# include <stddef.h>

typedef enum e_probe_state
{
	PROBE_PENDING = 0,
	PROBE_IN_FLIGHT,
	PROBE_DONE
}	t_probe_state;

typedef enum e_scan_result
{
	SCAN_RESULT_UNKNOWN = 0,
	SCAN_RESULT_OPEN,
	SCAN_RESULT_CLOSED,
	SCAN_RESULT_FILTERED,
	SCAN_RESULT_UNFILTERED,
	SCAN_RESULT_OPEN_FILTERED
}	t_scan_result;

typedef struct s_probe
{
	uint32_t		target_ip;
	uint16_t	dst_port;
	uint16_t	src_port;
	uint32_t	seq;

	uint32_t	scan_type;
	uint64_t	sent_at_ms;

	t_probe_state	state;
	t_scan_result	result;
}	t_probe;

typedef struct s_nmap_runtime
{
	t_probe	*probes;
	size_t	probe_count;

	size_t	next_to_send;
	size_t	done_count;
	size_t	in_flight_count;
}	t_nmap_runtime;

typedef enum e_nmap_reply_type
{
	NMAP_REPLY_NONE = 0,
	NMAP_REPLY_TCP,
	NMAP_REPLY_UDP,
	NMAP_REPLY_ICMP
}	t_nmap_reply_type;

typedef struct s_nmap_reply
{
	t_nmap_reply_type	type;

	uint32_t			src_ip;
	uint32_t			dst_ip;
	uint16_t			src_port;
	uint16_t			dst_port;

	uint8_t				tcp_flags;
	uint8_t				icmp_type;
	uint8_t				icmp_code;

	uint8_t				original_protocol;
	uint32_t			original_src_ip;
	uint32_t			original_dst_ip;
	uint16_t			original_src_port;
	uint16_t			original_dst_port;
}	t_nmap_reply;

#endif