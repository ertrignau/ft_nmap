#ifndef NMAP_PACKET_H
# define NMAP_PACKET_H

# include "config.h"
# include "packet/wire.h"

# include <stddef.h>
# include <stdint.h>

/* packet dispatch / raw send */
int			nmap_send_probe(t_nmap_config *config, t_probe *probe);
int			nmap_send_tcp_probe(t_nmap_config *config, t_probe *probe);
int			nmap_send_udp_probe(t_nmap_config *config, t_probe *probe);
int			nmap_send_raw_packet(t_nmap_config *config,
				const unsigned char *packet, size_t packet_len);

/* IP builders / transport pseudo-header checksums */
void		nmap_build_ipv4_header(t_nmap_config *config, t_probe *probe,
				t_nmap_ipv4_header *ip, uint8_t protocol, size_t payload_len);
void		nmap_build_ipv6_header(t_nmap_config *config,
				t_nmap_ipv6_header *ip, uint8_t next_header,
				size_t payload_len);
uint16_t	nmap_transport_checksum_ipv4(const t_nmap_config *config,
				uint8_t protocol, const void *transport, size_t len);
uint16_t	nmap_transport_checksum_ipv6(const t_nmap_config *config,
				uint8_t next_header, const void *transport, size_t len);

/* pcap parser */
int			nmap_parse_pcap_packet(t_nmap_config *config,
				const unsigned char *packet, size_t len,
				t_nmap_reply *reply);

/* Internet-checksum primitives */
uint32_t	nmap_checksum_add(uint32_t sum, const void *data, size_t len);
uint16_t	nmap_checksum_finish(uint32_t sum);
uint16_t	nmap_checksum(const void *data, size_t len);

#endif
