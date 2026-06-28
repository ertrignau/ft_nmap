#ifndef NMAP_DEBUG_H
# define NMAP_DEBUG_H

# include "config.h"
# include <stddef.h>
# include <stdint.h>

# ifndef NMAP_PROFILING_SECTION
#  define NMAP_PROFILING_SECTION

typedef enum e_nmap_prof_event
{
	NMAP_PROF_SELECT_REQUESTED = 0,
	NMAP_PROF_SELECT_WAIT,
	NMAP_PROF_PCAP_NEXT_EX,
	NMAP_PROF_PACKET_PARSE_TOTAL,
	NMAP_PROF_LINK_OFFSET,
	NMAP_PROF_IPV4_PARSE,
	NMAP_PROF_TCP_PARSE,
	NMAP_PROF_UDP_PARSE,
	NMAP_PROF_ICMP_PARSE,
	NMAP_PROF_MATCH_PROBE,
	NMAP_PROF_CLASSIFY,
	NMAP_PROF_EXPIRE,
	NMAP_PROF_SEND_BUILD,
	NMAP_PROF_SEND_SENDTO,

	NMAP_PROF_PACKET_SEEN,
	NMAP_PROF_PACKET_PARSED,
	NMAP_PROF_PACKET_IGNORED,
	NMAP_PROF_PACKET_MATCHED,
	NMAP_PROF_PACKET_TIMEOUT,
	NMAP_PROF_PROBE_SENT,

	NMAP_PROF_EVENT_COUNT
}	t_nmap_prof_event;

#  ifdef PROFILE

uint64_t	nmap_prof_now_us(void);
void		nmap_prof_add(t_nmap_prof_event event, uint64_t start_us);
void		nmap_prof_add_value(t_nmap_prof_event event, uint64_t elapsed_us);
void		nmap_prof_count(t_nmap_prof_event event);
void		nmap_prof_report(void);

#   define PROF_START() nmap_prof_now_us()
#   define PROF_ADD(event, start_us) nmap_prof_add((event), (start_us))
#   define PROF_ADD_VALUE(event, elapsed_us) \
	nmap_prof_add_value((event), (elapsed_us))
#   define PROF_COUNT(event) nmap_prof_count((event))
#   define PROF_REPORT() nmap_prof_report()

#  else

#   define PROF_START() ((uint64_t)0)
#   define PROF_ADD(event, start_us) ((void)(event), (void)(start_us))
#   define PROF_ADD_VALUE(event, elapsed_us) \
	((void)(event), (void)(elapsed_us))
#   define PROF_COUNT(event) ((void)(event))
#   define PROF_REPORT() ((void)0)

#  endif

# endif

# ifdef DEBUG

void	nmap_debug_dev_config(const t_nmap_config *config);
void	nmap_debug_socket(const t_nmap_config *config);
void	nmap_debug_pcap(const t_nmap_config *config);
void	nmap_debug_runtime(const t_nmap_config *config);

void	nmap_debug_probe_send(const t_probe *probe);
void	nmap_debug_probe_timeout(const t_probe *probe);
void	nmap_debug_probe_result(const t_probe *probe, const char *reason);

void	nmap_debug_hexdump(const char *title, const void *data, size_t len);

#  define DEBUG_DEV_CONFIG(config) \
	nmap_debug_dev_config(config)
#  define DEBUG_SOCKET(config) \
	nmap_debug_socket(config)
#  define DEBUG_PCAP(config) \
	nmap_debug_pcap(config)
#  define DEBUG_RUNTIME(config) \
	nmap_debug_runtime(config)

#  define DEBUG_PROBE_SEND(probe) \
	nmap_debug_probe_send(probe)
#  define DEBUG_PROBE_TIMEOUT(probe) \
	nmap_debug_probe_timeout(probe)
#  define DEBUG_PROBE_RESULT(probe, reason) \
	nmap_debug_probe_result(probe, reason)

#  define DEBUG_SEND_PACKET(data, len) \
	nmap_debug_hexdump("[debug][send][packet]", data, len)
#  define DEBUG_RECV_PACKET(data, len) \
	nmap_debug_hexdump("[debug][recv][packet]", data, len)

# else

#  define DEBUG_DEV_CONFIG(config) \
	((void)(config))
#  define DEBUG_SOCKET(config) \
	((void)(config))
#  define DEBUG_PCAP(config) \
	((void)(config))
#  define DEBUG_RUNTIME(config) \
	((void)(config))

#  define DEBUG_PROBE_SEND(probe) \
	((void)(probe))
#  define DEBUG_PROBE_TIMEOUT(probe) \
	((void)(probe))
#  define DEBUG_PROBE_RESULT(probe, reason) \
	((void)(probe), (void)(reason))

#  define DEBUG_SEND_PACKET(data, len) \
	((void)(data), (void)(len))
#  define DEBUG_RECV_PACKET(data, len) \
	((void)(data), (void)(len))

# endif

#endif