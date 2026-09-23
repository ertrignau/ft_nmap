
#include "config.h"
#include "net/address.h"

#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/**
 * @brief Ask the kernel which source address it would route to the target.
 */
static int	find_source_address(const t_nmap_target *target,
		t_nmap_ip_addr *src_addr, int *saved_error)
{
	struct sockaddr_storage	dst;
	struct sockaddr_storage	local;
	socklen_t				dst_len;
	socklen_t				local_len;
	int						fd;
	int						error;

	if (!nmap_ip_to_sockaddr(&target->addr, 1, &dst, &dst_len))
	{
		*saved_error = EAFNOSUPPORT;
		return (0);
	}
	fd = socket(target->addr.family, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0)
	{
		*saved_error = errno;
		return (0);
	}
	if (connect(fd, (struct sockaddr *)&dst, dst_len) < 0)
	{
		error = errno;
		close(fd);
		*saved_error = error;
		return (0);
	}
	memset(&local, 0, sizeof(local));
	local_len = sizeof(local);
	if (getsockname(fd, (struct sockaddr *)&local, &local_len) < 0)
	{
		error = errno;
		close(fd);
		*saved_error = error;
		return (0);
	}
	close(fd);
	if (!nmap_ip_from_sockaddr(src_addr,
			(struct sockaddr *)&local, local_len))
	{
		*saved_error = EAFNOSUPPORT;
		return (0);
	}
	return (1);
}

/**
 * @brief Find the interface owning the selected source address.
 *
 * expected_ifindex is zero for ordinary unscoped routes. For a scoped IPv6
 * target it forces the local source-address match to occur on the same zone,
 * avoiding an address-only comparison across different interfaces.
 */
static int	find_source_interface(const t_nmap_ip_addr *src_addr,
		unsigned int expected_ifindex, char *iface, size_t iface_size,
		unsigned int *ifindex, int *saved_error)
{
	struct ifaddrs	*ifaddr;
	struct ifaddrs	*current;
	t_nmap_ip_addr	current_addr;
	unsigned int	current_ifindex;
	size_t			name_len;
	socklen_t		addr_len;
	int				found;

	ifaddr = NULL;
	if (getifaddrs(&ifaddr) < 0)
	{
		*saved_error = errno;
		return (0);
	}
	found = 0;
	current = ifaddr;
	while (current)
	{
		if (src_addr->family == AF_INET)
			addr_len = sizeof(struct sockaddr_in);
		else
		{
			addr_len = sizeof(struct sockaddr_in6);
		}
		current_ifindex = 0;
		if (current->ifa_name)
			current_ifindex = if_nametoindex(current->ifa_name);
		if (current->ifa_name && current->ifa_addr
			&& (current->ifa_flags & IFF_UP)
			&& current->ifa_addr->sa_family == src_addr->family
			&& current_ifindex != 0
			&& (expected_ifindex == 0
				|| current_ifindex == expected_ifindex)
			&& nmap_ip_from_sockaddr(&current_addr,
				current->ifa_addr, addr_len)
			&& nmap_ip_equal(src_addr, &current_addr))
		{
			name_len = strlen(current->ifa_name);
			if (name_len >= iface_size)
			{
				freeifaddrs(ifaddr);
				*saved_error = ENAMETOOLONG;
				return (0);
			}
			memcpy(iface, current->ifa_name, name_len + 1);
			*ifindex = current_ifindex;
			found = 1;
			break ;
		}
		current = current->ifa_next;
	}
	freeifaddrs(ifaddr);
	if (!found)
	{
		*saved_error = ENODEV;
		return (0);
	}
	return (1);
}

/**
 * @brief Prepare source address, interface and scope for the current target.
 */
int	nmap_prepare_route(t_nmap_target_ctx *ctx, int *exit_status)
{
	unsigned int	expected_ifindex;
	int				error;

	if (!ctx || (ctx->target.addr.family != AF_INET
			&& ctx->target.addr.family != AF_INET6))
	{
		if (exit_status)
			*exit_status = 1;
		return (0);
	}
	if (ctx->target.addr.family == AF_INET6
		&& IN6_IS_ADDR_LINKLOCAL(&ctx->target.addr.addr.v6)
		&& ctx->target.addr.scope_id == 0)
	{
		fprintf(stderr,
			"ft_nmap: link-local IPv6 target %s requires a zone "
			"identifier (for example %%eth0)\n", ctx->target.name);
		if (exit_status)
			*exit_status = 1;
		return (0);
	}
	memset(&ctx->route, 0, sizeof(ctx->route));
	error = 0;
	if (!find_source_address(&ctx->target,
			&ctx->route.src_addr, &error))
	{
		fprintf(stderr, "ft_nmap: no route to %s: %s\n",
			ctx->target.ip, strerror(error));
		if (exit_status)
			*exit_status = 1;
		return (0);
	}
	if (!nmap_ip_ntop(&ctx->route.src_addr,
			ctx->route.src_ip, sizeof(ctx->route.src_ip)))
	{
		perror("ft_nmap: inet_ntop route source");
		if (exit_status)
			*exit_status = 1;
		return (0);
	}
	expected_ifindex = 0;
	if (ctx->target.addr.family == AF_INET6)
		expected_ifindex = ctx->target.addr.scope_id;
	if (expected_ifindex == 0 && ctx->route.src_addr.family == AF_INET6)
		expected_ifindex = ctx->route.src_addr.scope_id;
	if (!find_source_interface(&ctx->route.src_addr, expected_ifindex,
			ctx->route.iface, sizeof(ctx->route.iface),
			&ctx->route.ifindex, &error))
	{
		fprintf(stderr, "ft_nmap: cannot find interface for source %s: %s\n",
			ctx->route.src_ip, strerror(error));
		if (exit_status)
			*exit_status = 1;
		return (0);
	}
	return (1);
}
