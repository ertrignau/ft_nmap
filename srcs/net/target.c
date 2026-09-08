#include "config.h"
#include "net/address.h"

#include <netdb.h>
#include <stdio.h>
#include <string.h>

/**
 * @brief Resolve one target name into the first usable IPv4/IPv6 address.
 *
 * @param target Destination structure to fill.
 * @param target_name IPv4, IPv6, hostname or FQDN supplied by the parser.
 *
 * @return 1 on success, 0 on resolution failure.
 *
 * @note AF_UNSPEC is intentional. Address-family policy is now a network-layer
 *       concern instead of an IPv4 assumption embedded in the parser/runtime.
 */
static int	resolve_host(t_nmap_target *target, const char *target_name)
{
	struct addrinfo	hints;
	struct addrinfo	*results;
	struct addrinfo	*current;
	int				status;

	if (!target || !target_name || target_name[0] == '\0')
		return (0);
	memset(target, 0, sizeof(*target));
	target->name = target_name;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	results = NULL;
	status = getaddrinfo(target_name, NULL, &hints, &results);
	if (status != 0)
	{
		fprintf(stderr, "ft_nmap: %s: %s\n",
			target_name, gai_strerror(status));
		return (0);
	}
	current = results;
	while (current)
	{
		if (current->ai_addr
			&& (current->ai_family == AF_INET
				|| current->ai_family == AF_INET6)
			&& nmap_ip_from_sockaddr(&target->addr,
				current->ai_addr, current->ai_addrlen))
			break ;
		current = current->ai_next;
	}
	if (!current)
	{
		fprintf(stderr, "ft_nmap: %s: no usable IPv4/IPv6 address\n",
			target_name);
		freeaddrinfo(results);
		return (0);
	}
	if (!nmap_ip_ntop(&target->addr, target->ip, sizeof(target->ip)))
	{
		perror("ft_nmap: inet_ntop target");
		freeaddrinfo(results);
		return (0);
	}
	freeaddrinfo(results);
	return (1);
}

/**
 * @brief Prepare one current target from the owned target list.
 */
int	nmap_prepare_target(t_nmap_config *config, const char *target_name,
		int *exit_status)
{
	if (!config || !resolve_host(&config->target, target_name))
	{
		if (exit_status)
			*exit_status = 1;
		return (0);
	}
	return (1);
}
