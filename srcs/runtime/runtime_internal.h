
#ifndef NMAP_RUNTIME_INTERNAL_H
# define NMAP_RUNTIME_INTERNAL_H

# include "config.h"

/** Return a monotonic millisecond timestamp used by runtime deadlines. */
uint64_t		nmap_now_ms(void);

/** Return whether one logical probe belongs to the UDP scan family. */
int				nmap_probe_is_udp(const t_probe *probe);

/** Return whether a reply may still legally complete this logical probe. */
int				nmap_probe_can_match(const t_probe *probe);

/**
 * Atomically claim one QUEUED generation immediately before sendto().
 * snapshot may be NULL; when supplied it receives a race-free debug copy.
 */
int				nmap_runtime_begin_send(t_nmap_config *config, t_probe *probe,
					uint32_t dispatch_id, t_probe *snapshot);

/** Commit one successful physical send as OUTSTANDING when still relevant. */
void			nmap_runtime_complete_send(t_nmap_config *config, t_probe *probe,
					uint32_t dispatch_id, uint64_t sent_at_ms);

/**
 * Record one failed physical send.
 * Return 1 when the failure is fatal for the target, 0 when the send belonged
 * to a retry already made irrelevant by a valid late reply.
 */
int				nmap_runtime_fail_send(t_nmap_config *config, t_probe *probe,
					uint32_t dispatch_id);

/** Find and fully validate the logical probe corresponding to one reply. */
t_probe			*nmap_find_matching_probe(t_nmap_config *config,
					t_nmap_reply *reply);

/** Classify one already-matched network reply. */
t_scan_result	nmap_classify_reply(const t_nmap_config *config,
					const t_probe *probe, const t_nmap_reply *reply);

/** Classify final absence of any useful reply after retransmission policy. */
t_scan_result	nmap_classify_no_response(uint32_t scan_type);

/** Atomically finalize one logical probe and update runtime counters. */
void			nmap_mark_probe_done(t_nmap_config *config,
					t_probe *probe, t_scan_result result,
					t_scan_reason reason, const char *debug_reason);

#endif
