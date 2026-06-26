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
	size_t		i;
	uint16_t	port;

	i = 0;
	port = 1;
	while (port <= 1024)
	{
		if (i >= NMAP_MAX_PORTS)
			return (0);
		scan->ports[i] = port;
		i++;
		port++;
	}
	scan->port_count = i;
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
	config->cli.scan_mask = NMAP_SCAN_SYN;
	config->cli.timeout_ms = 1000;
	config->cli.max_in_flight = 50;

	if (!set_sockaddr_ipv4(&config->target.addr, &config->target.addr_len,
			config->target.ip, "172.28.0.10"))
		return (0);

	if (!set_route_ipv4(&config->route, "br-2fbd72aae601", "172.28.0.1"))
		return (0);

	if (!set_scan_ports(&config->scan))
		return (0);
	config->scan.scan_mask = NMAP_SCAN_SYN;
	config->scan.src_port_base = 40000;
	config->scan.timeout_ms = 1000;
	config->scan.max_in_flight = 50;

	return (1);
}