#ifndef NMAP_DEBUG_H
# define NMAP_DEBUG_H

# include "config.h"
# include <stddef.h>

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