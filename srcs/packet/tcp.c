#include "config.h"
#include "debug/debug.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

uint16_t	nmap_checksum(const void *data, size_t len);

typedef struct s_tcp_pseudo_header
{
	uint32_t	src_addr;
	uint32_t	dst_addr;
	uint8_t		zero;
	uint8_t		protocol;
	uint16_t	tcp_len;
}	t_tcp_pseudo_header;

/**
 * @brief Fill TCP flags according to the scan type.
 *
 * @param tcp TCP header to modify.
 * @param scan_type Probe scan type.
 *
 * @return 1 on success, 0 on unknown TCP scan type.
 */
static int	set_tcp_flags(struct tcphdr *tcp, uint32_t scan_type)
{
	if (scan_type == NMAP_SCAN_SYN)
		tcp->syn = 1;
	else if (scan_type == NMAP_SCAN_NULL)
		return (1);
	else if (scan_type == NMAP_SCAN_FIN)
		tcp->fin = 1;
	else if (scan_type == NMAP_SCAN_XMAS)
	{
		tcp->fin = 1;
		tcp->psh = 1;
		tcp->urg = 1;
	}
	else if (scan_type == NMAP_SCAN_ACK)
		tcp->ack = 1;
	else
		return (0);
	return (1);
}

/**
 * @brief Fill the IPv4 header for a raw TCP probe.
 *
 * @param config Global nmap configuration.
 * @param probe Runtime probe being sent.
 * @param ip IPv4 header to fill.
 * @param packet_len Full packet length in bytes.
 */
static void	build_ip_header(t_nmap_config *config, t_probe *probe,
		struct iphdr *ip, size_t packet_len)
{
	memset(ip, 0, sizeof(*ip));
	ip->ihl = 5;
	ip->version = 4;
	ip->tos = 0;
	ip->tot_len = htons((uint16_t)packet_len);
	ip->id = htons(probe->src_port);
	ip->frag_off = 0;
	ip->ttl = 64;
	ip->protocol = IPPROTO_TCP;
	ip->saddr = config->route.src_addr.sin_addr.s_addr;
	ip->daddr = probe->target_ip;
	ip->check = 0;
	ip->check = nmap_checksum(ip, sizeof(*ip));
}

/**
 * @brief Fill the TCP header for a runtime probe.
 *
 * @param probe Runtime probe being sent.
 * @param tcp TCP header to fill.
 *
 * @return 1 on success, 0 on unknown TCP scan type.
 */
static int	build_tcp_header(t_probe *probe, struct tcphdr *tcp)
{
	memset(tcp, 0, sizeof(*tcp));
	tcp->source = htons(probe->src_port);
	tcp->dest = htons(probe->dst_port);
	tcp->seq = htonl(probe->seq);
	tcp->ack_seq = 0;
	tcp->doff = sizeof(*tcp) / 4;
	tcp->window = htons(1024);
	tcp->check = 0;
	tcp->urg_ptr = 0;
	return (set_tcp_flags(tcp, probe->scan_type));
}

/**
 * @brief Compute and write the TCP checksum.
 *
 * @param config Global nmap configuration.
 * @param probe Runtime probe being sent.
 * @param tcp TCP header to checksum.
 */
static void	set_tcp_checksum(t_nmap_config *config, t_probe *probe,
		struct tcphdr *tcp)
{
	unsigned char			buffer[sizeof(t_tcp_pseudo_header)
		+ sizeof(struct tcphdr)];
	t_tcp_pseudo_header		pseudo;

	memset(&pseudo, 0, sizeof(pseudo));
	pseudo.src_addr = config->route.src_addr.sin_addr.s_addr;
	pseudo.dst_addr = probe->target_ip;
	pseudo.zero = 0;
	pseudo.protocol = IPPROTO_TCP;
	pseudo.tcp_len = htons(sizeof(struct tcphdr));
	memcpy(buffer, &pseudo, sizeof(pseudo));
	memcpy(buffer + sizeof(pseudo), tcp, sizeof(*tcp));
	tcp->check = nmap_checksum(buffer, sizeof(buffer));
}

/**
 * @brief Send one TCP probe as a raw IPv4 packet.
 *
 * @param config Global nmap configuration.
 * @param probe Runtime probe to send.
 *
 * @return 1 on success, 0 on build or send failure.
 *
 * @note The buffer dumped by DEBUG_SEND_PACKET() is the exact buffer passed to
 *       sendto().
 */
int	nmap_send_tcp_probe(t_nmap_config *config, t_probe *probe)
{
	unsigned char		packet[sizeof(struct iphdr) + sizeof(struct tcphdr)];
	struct iphdr		*ip;
	struct tcphdr		*tcp;
	struct sockaddr_in	dst;
	size_t				packet_len;
	ssize_t				sent;
	uint64_t			prof_start;

	if (!config || !probe)
		return (0);
	prof_start = PROF_START();
	packet_len = sizeof(packet);
	memset(packet, 0, sizeof(packet));
	ip = (struct iphdr *)packet;
	tcp = (struct tcphdr *)(packet + sizeof(struct iphdr));
	build_ip_header(config, probe, ip, packet_len);
	if (!build_tcp_header(probe, tcp))
	{
		PROF_ADD(NMAP_PROF_SEND_BUILD, prof_start);
		fprintf(stderr, "ft_nmap: invalid TCP scan type: 0x%x\n",
			probe->scan_type);
		return (0);
	}
	set_tcp_checksum(config, probe, tcp);
	PROF_ADD(NMAP_PROF_SEND_BUILD, prof_start);
	memset(&dst, 0, sizeof(dst));
	dst.sin_family = AF_INET;
	dst.sin_addr.s_addr = probe->target_ip;
	dst.sin_port = htons(probe->dst_port);
	DEBUG_SEND_PACKET(packet, packet_len);
	prof_start = PROF_START();
	sent = sendto(config->socket.send_fd, packet, packet_len, 0,
			(struct sockaddr *)&dst, sizeof(dst));
	PROF_ADD(NMAP_PROF_SEND_SENDTO, prof_start);
	if (sent < 0 || (size_t)sent != packet_len)
	{
		perror("ft_nmap: sendto");
		return (0);
	}
	PROF_COUNT(NMAP_PROF_PROBE_SENT);
	return (1);
}

