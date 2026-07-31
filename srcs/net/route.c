#include "config.h"

#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/**
 * @brief Ask the kernel which IPv4 source address it would use.
 *
 * @param target Resolved destination.
 * @param src_addr Output source address.
 * @param saved_error Output errno value on failure.
 *
 * @return 1 on success, 0 on failure.
 *
 * @note Connecting a UDP socket does not send a packet. It only associates
 *       the socket with a destination and lets the kernel perform route
 *       selection.
 */
static int	find_source_address(const t_nmap_target *target,
		struct sockaddr_in *src_addr, int *saved_error)
{
	struct sockaddr_in	dst_addr;
	socklen_t			addr_len;
	int					fd;
	int					error;

	fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0)
	{
		*saved_error = errno;
		return (0);
	}
	dst_addr = target->addr;
	dst_addr.sin_port = htons(1);
	if (connect(fd, (struct sockaddr *)&dst_addr,
			sizeof(dst_addr)) < 0)
	{
		error = errno;
		close(fd);
		*saved_error = error;
		return (0);
	}
	memset(src_addr, 0, sizeof(*src_addr));
	addr_len = sizeof(*src_addr);
	if (getsockname(fd, (struct sockaddr *)src_addr,
			&addr_len) < 0)
	{
		error = errno;
		close(fd);
		*saved_error = error;
		return (0);
	}
	close(fd);
	if (src_addr->sin_family != AF_INET
		|| addr_len < (socklen_t)sizeof(struct sockaddr_in))
	{
		*saved_error = EAFNOSUPPORT;
		return (0);
	}
	src_addr->sin_port = 0;
	return (1);
}

/**
 * @brief Find the interface owning one IPv4 source address.
 *
 * @param src_addr Source IPv4 address selected by the kernel.
 * @param iface Destination interface-name buffer.
 * @param iface_size Size of the interface-name buffer.
 * @param saved_error Output errno-style value on failure.
 *
 * @return 1 on success, 0 if no unique interface can be selected.
 */
static int	find_source_interface(const struct sockaddr_in *src_addr,
		char *iface, size_t iface_size, int *saved_error)
{
	struct ifaddrs			*ifaddr;
	struct ifaddrs			*current;
	const struct sockaddr_in	*current_addr;
	char					found_iface[64];
	size_t					name_len;
	int						found;

	ifaddr = NULL;
	if (getifaddrs(&ifaddr) < 0)
	{
		*saved_error = errno;
		return (0);
	}
	memset(found_iface, 0, sizeof(found_iface));
	found = 0;
	current = ifaddr;
	while (current)
	{
		if (current->ifa_name
			&& current->ifa_addr
			&& current->ifa_addr->sa_family == AF_INET
			&& (current->ifa_flags & IFF_UP))
		{
			current_addr
				= (const struct sockaddr_in *)current->ifa_addr;
			if (current_addr->sin_addr.s_addr
				== src_addr->sin_addr.s_addr)
			{
				name_len = strlen(current->ifa_name);
				if (name_len >= sizeof(found_iface)
					|| name_len >= iface_size)
				{
					freeifaddrs(ifaddr);
					*saved_error = ENAMETOOLONG;
					return (0);
				}
				if (!found)
				memcpy(found_iface, current->ifa_name,
					name_len + 1);
				else if (strcmp(found_iface,
						current->ifa_name) != 0)
				{
					freeifaddrs(ifaddr);
					*saved_error = EADDRNOTAVAIL;
					return (0);
				}
				found = 1;
			}
		}
		current = current->ifa_next;
	}
	freeifaddrs(ifaddr);
	if (!found)
	{
		*saved_error = ENODEV;
		return (0);
	}
	memcpy(iface, found_iface, strlen(found_iface) + 1);
	return (1);
}

/**
 * @brief Prepare the route used to reach the resolved target.
 *
 * @param config Global nmap configuration.
 * @param exit_status Output exit status set on route-resolution failure.
 *
 * @return 1 on success, 0 on failure.
 */
int	nmap_prepare_route(t_nmap_config *config, int *exit_status)
{
	int	error;

	if (!config
		|| config->target.addr.sin_family != AF_INET
		|| config->target.addr_len
			< (socklen_t)sizeof(struct sockaddr_in)
		|| config->target.ip[0] == '\0')
	{
		if (exit_status)
			*exit_status = 1;
		return (0);
	}
	memset(&config->route, 0, sizeof(config->route));
	error = 0;
	if (!find_source_address(&config->target,
			&config->route.src_addr, &error))
	{
		config->route.error = error;
		fprintf(stderr, "ft_nmap: no route to %s: %s\n",
			config->target.ip, strerror(error));
		if (exit_status)
			*exit_status = 1;
		return (0);
	}
	if (!inet_ntop(AF_INET, &config->route.src_addr.sin_addr,
			config->route.src_ip, sizeof(config->route.src_ip)))
	{
		config->route.error = errno;
		perror("ft_nmap: inet_ntop route source");
		if (exit_status)
			*exit_status = 1;
		return (0);
	}
	if (!find_source_interface(&config->route.src_addr,
			config->route.iface, sizeof(config->route.iface), &error))
	{
		config->route.error = error;
		fprintf(stderr,
			"ft_nmap: cannot find interface for source %s: %s\n",
			config->route.src_ip, strerror(error));
		if (exit_status)
			*exit_status = 1;
		return (0);
	}
	return (1);
}