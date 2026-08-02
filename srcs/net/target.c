
#include "config.h"

#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>

/**
 * @brief Resolve one target name into a usable IPv4 address.
 *
 * @param target Destination structure to fill.
 * @param target_name IPv4 address, hostname or FQDN.
 *
 * @return 0 on success, -1 on resolution failure.
 */
static int	resolve_host(t_nmap_target *target, const char *target_name)
{
	struct addrinfo				hints;
	struct addrinfo				*results;
	struct addrinfo				*current;
	const struct sockaddr_in	*addr;
	int						status;

	if (!target || !target_name || target_name[0] == '\0')
		return (-1);
	memset(target, 0, sizeof(*target));
	target->name = target_name;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	results = NULL;
	status = getaddrinfo(target_name, NULL, &hints, &results);
	if (status != 0)
	{
		target->gai_error = status;
		fprintf(stderr, "ft_nmap: %s: %s\n",
			target_name, gai_strerror(status));
		return (-1);
	}
	current = results;
	while (current && (!current->ai_addr
			|| current->ai_family != AF_INET
			|| current->ai_addrlen
				< (socklen_t)sizeof(struct sockaddr_in)))
		current = current->ai_next;
	if (!current)
	{
		fprintf(stderr, "ft_nmap: %s: no usable IPv4 address\n",
			target_name);
		freeaddrinfo(results);
		return (-1);
	}
	addr = (const struct sockaddr_in *)current->ai_addr;
	target->addr = *addr;
	target->addr.sin_port = 0;
	target->addr_len = sizeof(target->addr);
	if (!inet_ntop(AF_INET, &target->addr.sin_addr,
			target->ip, sizeof(target->ip)))
	{
		target->error = errno;
		perror("ft_nmap: inet_ntop");
		freeaddrinfo(results);
		return (-1);
	}
	freeaddrinfo(results);
	return (0);
}

/**
 * @brief Prepare one current target from the owned target list.
 *
 * @param config Global nmap configuration.
 * @param target_name Target text selected by the main loop.
 * @param exit_status Output exit status set on resolution failure.
 *
 * @return 1 on success, 0 on failure.
 */
int	nmap_prepare_target(t_nmap_config *config, const char *target_name,
		int *exit_status)
{
	if (!config || !target_name || target_name[0] == '\0')
	{
		if (exit_status)
			*exit_status = 1;
		return (0);
	}
	if (resolve_host(&config->target, target_name) < 0)
	{
		if (exit_status)
			*exit_status = 1;
		return (0);
	}
	return (1);
}
