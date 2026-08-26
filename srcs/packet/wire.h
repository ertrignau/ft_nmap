#ifndef NMAP_PACKET_WIRE_H
# define NMAP_PACKET_WIRE_H

# include <netinet/in.h>
# include <stdint.h>

# define NMAP_IPV4_HEADER_LEN 20
# define NMAP_IPV6_HEADER_LEN 40
# define NMAP_TCP_HEADER_LEN 20
# define NMAP_UDP_HEADER_LEN 8

# define NMAP_TCP_FIN 0x01
# define NMAP_TCP_SYN 0x02
# define NMAP_TCP_RST 0x04
# define NMAP_TCP_PSH 0x08
# define NMAP_TCP_ACK 0x10
# define NMAP_TCP_URG 0x20

/**
 * @brief Minimal IPv4 header written directly to the raw send buffer.
 *
 * @note Wire structs are packed and compile-time size checked. Runtime/business
 *       structures must not depend on this representation.
 */
typedef struct __attribute__((packed)) s_nmap_ipv4_header
{
	uint8_t			version_ihl;
	uint8_t			tos;
	uint16_t		total_length;
	uint16_t		identification;
	uint16_t		fragment_offset;
	uint8_t			ttl;
	uint8_t			protocol;
	uint16_t		checksum;
	struct in_addr	src;
	struct in_addr	dst;
}	t_nmap_ipv4_header;

/**
 * @brief Fixed 40-byte IPv6 base header.
 */
typedef struct __attribute__((packed)) s_nmap_ipv6_header
{
	uint32_t		version_tc_flow;
	uint16_t		payload_length;
	uint8_t			next_header;
	uint8_t			hop_limit;
	struct in6_addr	src;
	struct in6_addr	dst;
}	t_nmap_ipv6_header;

/**
 * @brief Minimal TCP header used by all TCP scan types.
 */
typedef struct __attribute__((packed)) s_nmap_tcp_header
{
	uint16_t	src_port;
	uint16_t	dst_port;
	uint32_t	seq;
	uint32_t	ack;
	uint8_t		data_offset;
	uint8_t		flags;
	uint16_t	window;
	uint16_t	checksum;
	uint16_t	urgent;
}	t_nmap_tcp_header;

/**
 * @brief UDP header used by the generic empty UDP probe.
 */
typedef struct __attribute__((packed)) s_nmap_udp_header
{
	uint16_t	src_port;
	uint16_t	dst_port;
	uint16_t	length;
	uint16_t	checksum;
}	t_nmap_udp_header;

_Static_assert(sizeof(t_nmap_ipv4_header) == NMAP_IPV4_HEADER_LEN,
	"invalid IPv4 wire header size");
_Static_assert(sizeof(t_nmap_ipv6_header) == NMAP_IPV6_HEADER_LEN,
	"invalid IPv6 wire header size");
_Static_assert(sizeof(t_nmap_tcp_header) == NMAP_TCP_HEADER_LEN,
	"invalid TCP wire header size");
_Static_assert(sizeof(t_nmap_udp_header) == NMAP_UDP_HEADER_LEN,
	"invalid UDP wire header size");

#endif
