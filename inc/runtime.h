
#ifndef NMAP_RUNTIME_H
# define NMAP_RUNTIME_H

# include "ip_addr.h"

# include <pthread.h>
# include <stddef.h>
# include <stdint.h>

/**
 * @brief Runtime lifecycle of one logical probe.
 *
 * PENDING      ready for the scheduler.
 * QUEUED       one dispatch generation is reserved; it may still be waiting
 *              in the sender queue or currently executing sendto().
 * OUTSTANDING  sendto() completed successfully and its timeout clock is live.
 * DONE         final scan result has been produced.
 *
 * @note A logical probe survives retransmissions. A retry does not allocate a
 *       second probe object; the same probe returns to PENDING.
 */
typedef enum e_probe_state
{
	PROBE_PENDING = 0,
	PROBE_QUEUED,
	PROBE_OUTSTANDING,
	PROBE_DONE
}	t_probe_state;

/**
 * @brief Final semantic states exposed by the scanner.
 */
typedef enum e_scan_result
{
	SCAN_RESULT_UNKNOWN = 0,
	SCAN_RESULT_OPEN,
	SCAN_RESULT_CLOSED,
	SCAN_RESULT_FILTERED,
	SCAN_RESULT_UNFILTERED,
	SCAN_RESULT_OPEN_FILTERED
}	t_scan_result;

/**
 * @brief Stable reason category retained by a completed logical probe.
 */
typedef enum e_scan_reason_kind
{
	SCAN_REASON_NONE = 0,
	SCAN_REASON_TCP,
	SCAN_REASON_UDP_REPLY,
	SCAN_REASON_ICMP,
	SCAN_REASON_NO_RESPONSE,
	SCAN_REASON_SEND_ERROR
}	t_scan_reason_kind;

/**
 * @brief Structured evidence that produced one final scan result.
 *
 * The runtime keeps protocol facts, not presentation text. report.c is free to
 * turn TCP flags or ICMP family/type/code into a human-readable --reason.
 */
typedef struct s_scan_reason
{
	t_scan_reason_kind	kind;
	sa_family_t			family;
	uint8_t				tcp_flags;
	uint8_t				icmp_type;
	uint8_t				icmp_code;
}	t_scan_reason;

/**
 * @brief One logical scan probe for one destination port and scan type.
 *
 * @note Target/source IP addresses deliberately do not live here. The current
 *       runtime scans one resolved target at a time; family/address ownership
 *       belongs to config.target/config.route instead of being duplicated in
 *       every probe.
 *
 * @note sending_dispatch_id is a transient execution token. A worker sets it
 *       only after validating the current QUEUED generation and immediately
 *       before sendto(). This lets a very fast reply match without lying that
 *       the probe is already OUTSTANDING. OUTSTANDING is committed only after
 *       sendto() succeeds.
 */
typedef struct s_probe
{
	uint16_t		dst_port;
	uint16_t		src_port;
	uint32_t		seq;
	uint32_t		scan_type;
	uint64_t		sent_at_ms;
	uint8_t			attempts_sent;
	uint32_t		dispatch_id;
	uint32_t		sending_dispatch_id;
	t_probe_state	state;
	t_scan_result	result;
	t_scan_reason	reason;
}	t_probe;

/**
 * @brief Parsed network reply kind.
 */
typedef enum e_nmap_reply_type
{
	NMAP_REPLY_NONE = 0,
	NMAP_REPLY_TCP,
	NMAP_REPLY_UDP,
	NMAP_REPLY_ICMP4,
	NMAP_REPLY_ICMP6
}	t_nmap_reply_type;

/**
 * @brief Protocol-independent parsed representation of one captured reply.
 *
 * Direct TCP/UDP replies fill src/dst addresses and ports. ICMP errors also
 * fill the embedded original packet fields, which are required to match the
 * error back to the exact logical probe.
 */
typedef struct s_nmap_reply
{
	t_nmap_reply_type	type;

	t_nmap_ip_addr		src_addr;
	t_nmap_ip_addr		dst_addr;
	uint16_t			src_port;
	uint16_t			dst_port;

	uint8_t				tcp_flags;
	uint32_t			tcp_seq;
	uint32_t			tcp_ack;

	uint8_t				icmp_type;
	uint8_t				icmp_code;

	uint8_t				original_protocol;
	t_nmap_ip_addr		original_src_addr;
	t_nmap_ip_addr		original_dst_addr;
	uint16_t			original_src_port;
	uint16_t			original_dst_port;
	uint32_t			original_tcp_seq;
	int					has_original_tcp_seq;
}	t_nmap_reply;

/**
 * @brief Runtime state for the current target.
 *
 * @note probe_by_src_port gives O(1) candidate lookup. The candidate is still
 *       fully validated before a captured packet is accepted.
 */
typedef struct s_nmap_runtime
{
	t_probe			*probes;
	t_probe			**probe_by_src_port;
	size_t			probe_count;

	size_t			done_count;
	size_t			queued_count;
	size_t			outstanding_count;
	size_t			udp_queued_count;
	size_t			udp_outstanding_count;

	uint16_t		source_port_base;
	uint64_t		last_udp_sent_ms;

	pthread_mutex_t	lock;
	int				lock_initialized;
}	t_nmap_runtime;

#endif
