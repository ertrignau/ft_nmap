#include "ft_nmap.h"

#include <string.h>
#include <arpa/inet.h>

static int	set_sockaddr_ipv4(struct sockaddr_in *addr,
		socklen_t *addr_len, char ip_str[INET_ADDRSTRLEN], const char *ip)
{
	struct in_addr	parsed;

	if (inet_pton(AF_INET, ip, &parsed) != 1)
		return (0);
	memset(addr, 0, sizeof(*addr));
	addr->sin_family = AF_INET;
	addr->sin_addr = parsed;
	if (addr_len)
		*addr_len = sizeof(*addr);
	memset(ip_str, 0, INET_ADDRSTRLEN);
	strncpy(ip_str, ip, INET_ADDRSTRLEN - 1);
	return (1);
}

static int	set_route_ipv4(t_nmap_route *route, const char *iface,
		const char *src_ip)
{
	if (!set_sockaddr_ipv4(&route->src_addr, NULL, route->src_ip, src_ip))
		return (0);
	memset(route->iface, 0, sizeof(route->iface));
	strncpy(route->iface, iface, sizeof(route->iface) - 1);
	return (1);
}

static int	set_scan_ports(t_nmap_scan *scan)
{
	static const uint16_t	ports[] = {
		1, 7, 9, 13, 17, 19,
		21, 22, 23, 25, 37, 42, 49, 53,
		67, 68, 69, 80, 81, 88,
		110, 111, 113, 119, 123,
		135, 137, 138, 139,
		143, 161, 162, 389, 443, 445,
		500, 514, 515, 520, 587, 631, 993, 1021
	};
	size_t					i;
	size_t					count;

	if (!scan)
		return (0);
	count = sizeof(ports) / sizeof(ports[0]);
	if (count > NMAP_MAX_PORTS)
		return (0);
	i = 0;
	while (i < count)
	{
		scan->ports[i] = ports[i];
		i++;
	}
	scan->port_count = count;
	return (1);
}

/*
 * TODO: DELETE
 *
 * Bypass temporaire du parsing, du resolve et de la détection de route.
 * Cette fonction existe uniquement pour tester le moteur réseau du MVP.
 */
int	nmap_load_hardcoded_dev_config(t_nmap_config *config)
{
	if (!config)
		return (0);
	memset(config, 0, sizeof(*config));

	config->socket.send_fd = -1;
	config->capture.handle = NULL;
	config->capture.fd = -1;
	config->capture.datalink = -1;

	config->cli.program_name = "./ft_nmap";
	config->cli.target = "172.28.0.10";
	config->cli.ports_arg = "20-25";
	config->cli.hide_uninteresting = 1;
	config->cli.scan_mask = (NMAP_SCAN_SYN | NMAP_SCAN_NULL
			| NMAP_SCAN_FIN | NMAP_SCAN_XMAS | NMAP_SCAN_ACK
			| NMAP_SCAN_UDP);
	config->cli.timeout_ms = 1000;
	config->cli.max_in_flight = 50;
	config->cli.speedup = 0;

	if (!set_sockaddr_ipv4(&config->target.addr, &config->target.addr_len,
			config->target.ip, "172.28.0.10"))
		return (0);

	if (!set_route_ipv4(&config->route, "br-39b82ea55216", "172.28.0.1"))
		return (0);

	if (!set_scan_ports(&config->scan))
		return (0);
	config->scan.scan_mask = config->cli.scan_mask;
	config->scan.src_port_base = 40000;

	config->scan.timeout_ms = 1000;
	config->scan.tcp_timeout_ms = 1000;
	config->scan.udp_timeout_ms = 2500;

	config->scan.max_in_flight = 1000;
	config->scan.max_outstanding_per_worker = 1;
	config->scan.udp_max_in_flight = 10;

	config->scan.tcp_send_gap_ms = 0;
	config->scan.udp_dispatch_gap_ms = 50;

	return (1);
}