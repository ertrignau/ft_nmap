#!/usr/bin/env python3
from pathlib import Path

def replace_exact(path, old, new):
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(path)
    text = p.read_text()
    if old not in text:
        raise RuntimeError(f"pattern not found in {path}:\n{old[:300]}")
    p.write_text(text.replace(old, new, 1))

def write_file(path, content):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)

def patch_signal():
    replace_exact(
        "srcs/signal/signal.c",
        '#include "ft_nmap.h"\n\n',
        "",
    )

def patch_checksum():
    write_file("srcs/packet/checksum.c", r'''#include <stddef.h>
#include <stdint.h>
#include <arpa/inet.h>

/**
 * @brief Compute the Internet checksum.
 *
 * @param data Buffer to checksum.
 * @param len Buffer length in bytes.
 *
 * @return 16-bit Internet checksum ready to be written in the packet.
 */
uint16_t	nmap_checksum(const void *data, size_t len)
{
	const uint8_t	*bytes;
	uint32_t		sum;
	uint16_t		word;

	bytes = (const uint8_t *)data;
	sum = 0;
	while (len > 1)
	{
		word = ((uint16_t)bytes[0] << 8) | bytes[1];
		sum += word;
		bytes += 2;
		len -= 2;
	}
	if (len == 1)
		sum += ((uint16_t)bytes[0] << 8);
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return (htons((uint16_t)(~sum)));
}
''')

def patch_udp():
    write_file("srcs/packet/udp.c", r'''#include "config.h"
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
''')

def patch_init_seq():
    replace_exact(
        "srcs/runtime/init.c",
        "	probe->seq = 0;",
        "	probe->seq = 0x10000000u + (uint32_t)index;",
    )

def patch_recv():
    path = "srcs/runtime/recv.c"

    replace_exact(
        path,
        "#include <stdio.h>\n#include <pcap/pcap.h>",
        "#include <stdio.h>\n#include <netinet/in.h>\n#include <pcap/pcap.h>",
    )

    replace_exact(
        path,
r'''static int	reply_matches_direct_probe(t_probe *probe, t_nmap_reply *reply)
{
	if (reply->src_ip != probe->target_ip)
		return (0);
	if (reply->src_port != probe->dst_port)
		return (0);
	if (reply->dst_port != probe->src_port)
		return (0);
	if (reply->type == NMAP_REPLY_TCP && probe->scan_type != NMAP_SCAN_UDP)
		return (1);
	if (reply->type == NMAP_REPLY_UDP && probe->scan_type == NMAP_SCAN_UDP)
		return (1);
	return (0);
}''',
r'''static int	reply_matches_direct_probe(t_nmap_config *config,
		t_probe *probe, t_nmap_reply *reply)
{
	if (reply->src_ip != probe->target_ip)
		return (0);
	if (reply->dst_ip != config->route.src_addr.sin_addr.s_addr)
		return (0);
	if (reply->src_port != probe->dst_port)
		return (0);
	if (reply->dst_port != probe->src_port)
		return (0);
	if (reply->type == NMAP_REPLY_TCP && probe->scan_type != NMAP_SCAN_UDP)
		return (1);
	if (reply->type == NMAP_REPLY_UDP && probe->scan_type == NMAP_SCAN_UDP)
		return (1);
	return (0);
}''',
    )

    replace_exact(
        path,
r'''static int	reply_matches_icmp_probe(t_probe *probe, t_nmap_reply *reply)
{
	if (reply->original_dst_ip != probe->target_ip)
		return (0);
	if (reply->original_dst_port != probe->dst_port)
		return (0);
	if (reply->original_src_port != probe->src_port)
		return (0);
	if (reply->original_protocol == IPPROTO_TCP
		&& probe->scan_type != NMAP_SCAN_UDP)
		return (1);
	if (reply->original_protocol == IPPROTO_UDP
		&& probe->scan_type == NMAP_SCAN_UDP)
		return (1);
	return (0);
}''',
r'''static int	reply_matches_icmp_probe(t_nmap_config *config,
		t_probe *probe, t_nmap_reply *reply)
{
	if (reply->original_src_ip != config->route.src_addr.sin_addr.s_addr)
		return (0);
	if (reply->original_dst_ip != probe->target_ip)
		return (0);
	if (reply->original_dst_port != probe->dst_port)
		return (0);
	if (reply->original_src_port != probe->src_port)
		return (0);
	if (reply->original_protocol == IPPROTO_TCP
		&& probe->scan_type != NMAP_SCAN_UDP)
		return (1);
	if (reply->original_protocol == IPPROTO_UDP
		&& probe->scan_type == NMAP_SCAN_UDP)
		return (1);
	return (0);
}''',
    )

    replace_exact(
        path,
r'''static int	reply_matches_probe(t_probe *probe, t_nmap_reply *reply)
{
	if (probe->state != PROBE_IN_FLIGHT)
		return (0);
	if (reply->type == NMAP_REPLY_TCP || reply->type == NMAP_REPLY_UDP)
		return (reply_matches_direct_probe(probe, reply));
	if (reply->type == NMAP_REPLY_ICMP)
		return (reply_matches_icmp_probe(probe, reply));
	return (0);
}''',
r'''static int	reply_matches_probe(t_nmap_config *config,
		t_probe *probe, t_nmap_reply *reply)
{
	if (probe->state != PROBE_IN_FLIGHT)
		return (0);
	if (reply->type == NMAP_REPLY_TCP || reply->type == NMAP_REPLY_UDP)
		return (reply_matches_direct_probe(config, probe, reply));
	if (reply->type == NMAP_REPLY_ICMP)
		return (reply_matches_icmp_probe(config, probe, reply));
	return (0);
}''',
    )

    replace_exact(
        path,
        "		if (reply_matches_probe(&config->runtime.probes[i], reply))",
        "		if (reply_matches_probe(config, &config->runtime.probes[i], reply))",
    )

def main():
    patch_signal()
    patch_checksum()
    patch_udp()
    patch_init_seq()
    patch_recv()
    print("inconsistency patch applied")

if __name__ == "__main__":
    main()