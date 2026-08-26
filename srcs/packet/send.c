#include "packet/packet.h"
#include "debug/debug.h"
#include "net/address.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

/**
 * @brief Return whether a scan type is transported over TCP.
 */
static int	is_tcp_scan(uint32_t scan_type)
{
	return (scan_type == NMAP_SCAN_SYN
		|| scan_type == NMAP_SCAN_NULL
		|| scan_type == NMAP_SCAN_FIN
		|| scan_type == NMAP_SCAN_XMAS
		|| scan_type == NMAP_SCAN_ACK);
}

/**
 * @brief Send one already-built complete IPv4/IPv6 packet.
 *
 * @note This is the only packet-layer function that calls sendto(). Builders
 *       remain testable without a live raw socket.
 */
int	nmap_send_raw_packet(t_nmap_config *config,
		const unsigned char *packet, size_t packet_len)
{
	struct sockaddr_storage	dst;
	socklen_t				dst_len;
	ssize_t					sent;
	uint64_t				prof_start;

	if (!config || !packet || packet_len == 0
		|| config->socket.send_fd < 0
		|| config->socket.family != config->target.addr.family)
		return (0);
	if (!nmap_ip_to_sockaddr(&config->target.addr, 0, &dst, &dst_len))
		return (0);
	DEBUG_SEND_PACKET(packet, packet_len);
	prof_start = PROF_START();
	sent = sendto(config->socket.send_fd, packet, packet_len, 0,
			(struct sockaddr *)&dst, dst_len);
	PROF_ADD(NMAP_PROF_SEND_SENDTO, prof_start);
	if (sent < 0 || (size_t)sent != packet_len)
	{
		fprintf(stderr, "ft_nmap: sendto: %s\n", strerror(errno));
		return (0);
	}
	PROF_COUNT(NMAP_PROF_PROBE_SENT);
	return (1);
}

/**
 * @brief Dispatch one runtime probe to its TCP or UDP packet builder.
 *
 * @note IP version is deliberately not selected here. TCP/UDP builders inspect
 *       the current target family and call the appropriate IP encapsulation.
 */
int	nmap_send_probe(t_nmap_config *config, t_probe *probe)
{
	if (!config || !probe)
		return (0);
	if (is_tcp_scan(probe->scan_type))
		return (nmap_send_tcp_probe(config, probe));
	if (probe->scan_type == NMAP_SCAN_UDP)
		return (nmap_send_udp_probe(config, probe));
	fprintf(stderr, "ft_nmap: invalid scan type: 0x%x\n", probe->scan_type);
	return (0);
}
