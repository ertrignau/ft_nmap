#include "config.h"
#include "net/address.h"

#include <errno.h>
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
 * @note AF_UNSPEC is intentional. Address-family policy belongs to the
 *       network layer instead of being an IPv4 assumption in the parser.
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
			&& current->ai_family == AF_INET
			&& nmap_ip_from_sockaddr(&target->addr,
				current->ai_addr, current->ai_addrlen))
			break ;
		current = current->ai_next;
	}
	if (!current)
	{
	current = results;
	while (current)
	{
		if (current->ai_addr
			&& current->ai_family == AF_INET6
			&& nmap_ip_from_sockaddr(&target->addr,
				current->ai_addr, current->ai_addrlen))
			break ;
		current = current->ai_next;
	}
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
		fprintf(stderr, "ft_nmap: cannot format resolved address for %s\n",
			target_name);
		freeaddrinfo(results);
		return (0);
	}
	freeaddrinfo(results);
	return (1);
}

/**
 * @brief Return whether the user supplied a numeric IPv4/IPv6 target.
 *
 * AI_NUMERICHOST guarantees that this check never performs a DNS lookup.
 */
static int	target_is_numeric(const char *target_name)
{
	struct addrinfo	hints;
	struct addrinfo	*result;
	int				status;

	if (!target_name || target_name[0] == '\0')
		return (0);
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_NUMERICHOST;
	result = NULL;
	status = getaddrinfo(target_name, NULL, &hints, &result);
	if (status == 0)
		freeaddrinfo(result);
	return (status == 0);
}

/**
 * @brief Try a PTR/reverse-DNS lookup for the already resolved target.
 *
 * Failure is deliberately silent: reverse DNS is optional presentation data,
 * never a condition for scanning the target successfully.
 */
static void	resolve_reverse_dns(t_nmap_target *target)
{
	struct sockaddr_storage	addr;
	socklen_t				addr_len;
	int						status;

	if (!target)
		return ;
	target->hostname[0] = '\0';
	if (!nmap_ip_to_sockaddr(&target->addr, 0, &addr, &addr_len))
		return ;
	status = getnameinfo((const struct sockaddr *)&addr, addr_len,
			target->hostname, sizeof(target->hostname),
			NULL, 0, NI_NAMEREQD);
	if (status != 0)
		target->hostname[0] = '\0';
}

/**
 * @brief Prepare one current target from the owned target list.
 *
 * --no-dns only disables the optional reverse lookup. Forward resolution of a
 * user-supplied hostname remains necessary to obtain the destination address.
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
	if (!config->scan.no_dns
		&& target_is_numeric(target_name))
		resolve_reverse_dns(&config->target);
	return (1);
}
