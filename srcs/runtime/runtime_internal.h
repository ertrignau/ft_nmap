#ifndef NMAP_RUNTIME_INTERNAL_H
# define NMAP_RUNTIME_INTERNAL_H

# include "config.h"

/** Return a millisecond timestamp used by the runtime timing policy. */
uint64_t		nmap_now_ms(void);

/** Return whether one logical probe belongs to the UDP scan family. */
int				nmap_probe_is_udp(const t_probe *probe);

/** Return whether a reply may still legally complete this logical probe. */
int				nmap_probe_can_match(const t_probe *probe);

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
