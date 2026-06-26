#include "config.h"
#include "debug/debug.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

uint16_t	nmap_checksum(const void *data, size_t len);

typedef struct s_udp_pseudo_header
{
	uint32_t	src_addr;
	uint32_t	dst_addr;
	uint8_t		zero;
	uint8_t		protocol;
	uint16_t	udp_len;
}	t_udp_pseudo_header;

/**
 * @brief Fill the IPv4 header for a raw UDP probe.
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
	ip->protocol = IPPROTO_UDP;
	ip->saddr = config->route.src_addr.sin_addr.s_addr;
	ip->daddr = probe->target_ip;
	ip->check = 0;
	ip->check = nmap_checksum(ip, sizeof(*ip));
}

/**
 * @brief Fill the UDP header for a runtime probe.
 *
 * @param probe Runtime probe being sent.
 * @param udp UDP header to fill.
 */
static void	build_udp_header(t_probe *probe, struct udphdr *udp)
{
	memset(udp, 0, sizeof(*udp));
	udp->source = htons(probe->src_port);
	udp->dest = htons(probe->dst_port);
	udp->len = htons(sizeof(struct udphdr));
	udp->check = 0;
}

/**
 * @brief Compute and write the UDP checksum.
 *
 * @param config Global nmap configuration.
 * @param probe Runtime probe being sent.
 * @param udp UDP header to checksum.
 */
static void	set_udp_checksum(t_nmap_config *config, t_probe *probe,
		struct udphdr *udp)
{
	unsigned char			buffer[sizeof(t_udp_pseudo_header)
		+ sizeof(struct udphdr)];
	t_udp_pseudo_header		pseudo;

	memset(&pseudo, 0, sizeof(pseudo));
	pseudo.src_addr = config->route.src_addr.sin_addr.s_addr;
	pseudo.dst_addr = probe->target_ip;
	pseudo.zero = 0;
	pseudo.protocol = IPPROTO_UDP;
	pseudo.udp_len = htons(sizeof(struct udphdr));
	memcpy(buffer, &pseudo, sizeof(pseudo));
	memcpy(buffer + sizeof(pseudo), udp, sizeof(*udp));
	udp->check = nmap_checksum(buffer, sizeof(buffer));
	if (udp->check == 0)
		udp->check = 0xffff;
}

/**
 * @brief Send one UDP probe as a raw IPv4 packet.
 *
 * @param config Global nmap configuration.
 * @param probe Runtime probe to send.
 *
 * @return 1 on success, 0 on build or send failure.
 *
 * @note The UDP probe currently has no payload. Payload profiles can be added
 *       later without changing the runtime scheduler.
 */
int	nmap_send_udp_probe(t_nmap_config *config, t_probe *probe)
{
	unsigned char		packet[sizeof(struct iphdr) + sizeof(struct udphdr)];
	struct iphdr		*ip;
	struct udphdr		*udp;
	struct sockaddr_in	dst;
	size_t				packet_len;
	ssize_t				sent;

	if (!config || !probe)
		return (0);
	packet_len = sizeof(packet);
	memset(packet, 0, sizeof(packet));
	ip = (struct iphdr *)packet;
	udp = (struct udphdr *)(packet + sizeof(struct iphdr));
	build_ip_header(config, probe, ip, packet_len);
	build_udp_header(probe, udp);
	set_udp_checksum(config, probe, udp);
	memset(&dst, 0, sizeof(dst));
	dst.sin_family = AF_INET;
	dst.sin_addr.s_addr = probe->target_ip;
	dst.sin_port = htons(probe->dst_port);
	DEBUG_SEND_PACKET(packet, packet_len);
	sent = sendto(config->socket.send_fd, packet, packet_len, 0,
			(struct sockaddr *)&dst, sizeof(dst));
	if (sent < 0 || (size_t)sent != packet_len)
	{
		perror("ft_nmap: sendto");
		return (0);
	}
	return (1);
}
