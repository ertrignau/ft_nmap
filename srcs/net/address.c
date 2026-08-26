#include "net/address.h"

#include <arpa/inet.h>
#include <string.h>

/**
 * @brief Normalize sockaddr_in/sockaddr_in6 into t_nmap_ip_addr.
 *
 * @param dst Destination semantic address.
 * @param src Source sockaddr returned by a system API.
 * @param src_len Size of src.
 *
 * @return 1 for AF_INET/AF_INET6, 0 for unsupported/truncated addresses.
 */
int	nmap_ip_from_sockaddr(t_nmap_ip_addr *dst,
		const struct sockaddr *src, socklen_t src_len)
{
	const struct sockaddr_in	*src4;
	const struct sockaddr_in6	*src6;

	if (!dst || !src)
		return (0);
	memset(dst, 0, sizeof(*dst));
	if (src->sa_family == AF_INET
		&& src_len >= (socklen_t)sizeof(struct sockaddr_in))
	{
		src4 = (const struct sockaddr_in *)src;
		dst->family = AF_INET;
		dst->addr.v4 = src4->sin_addr;
		return (1);
	}
	if (src->sa_family == AF_INET6
		&& src_len >= (socklen_t)sizeof(struct sockaddr_in6))
	{
		src6 = (const struct sockaddr_in6 *)src;
		dst->family = AF_INET6;
		dst->addr.v6 = src6->sin6_addr;
		dst->scope_id = src6->sin6_scope_id;
		return (1);
	}
	return (0);
}

/**
 * @brief Build a sockaddr_storage for connect()/sendto()/other socket APIs.
 *
 * @param src Scanner semantic address.
 * @param port Host-order transport port to store in the sockaddr.
 * @param dst Destination storage.
 * @param dst_len Output concrete sockaddr size.
 *
 * @return 1 on success, 0 for unsupported families.
 */
int	nmap_ip_to_sockaddr(const t_nmap_ip_addr *src, uint16_t port,
		struct sockaddr_storage *dst, socklen_t *dst_len)
{
	struct sockaddr_in	*dst4;
	struct sockaddr_in6	*dst6;

	if (!src || !dst || !dst_len)
		return (0);
	memset(dst, 0, sizeof(*dst));
	if (src->family == AF_INET)
	{
		dst4 = (struct sockaddr_in *)dst;
		dst4->sin_family = AF_INET;
		dst4->sin_port = htons(port);
		dst4->sin_addr = src->addr.v4;
		*dst_len = sizeof(*dst4);
		return (1);
	}
	if (src->family == AF_INET6)
	{
		dst6 = (struct sockaddr_in6 *)dst;
		dst6->sin6_family = AF_INET6;
		dst6->sin6_port = htons(port);
		dst6->sin6_addr = src->addr.v6;
		dst6->sin6_scope_id = src->scope_id;
		*dst_len = sizeof(*dst6);
		return (1);
	}
	return (0);
}

/**
 * @brief Compare two IP addresses independently of IPv6 scope metadata.
 *
 * @note The scope id selects a local interface for scoped IPv6 destinations;
 *       it is not part of the source/destination address carried by a packet.
 */
int	nmap_ip_equal(const t_nmap_ip_addr *a, const t_nmap_ip_addr *b)
{
	if (!a || !b || a->family != b->family)
		return (0);
	if (a->family == AF_INET)
		return (memcmp(&a->addr.v4, &b->addr.v4,
				sizeof(a->addr.v4)) == 0);
	if (a->family == AF_INET6)
		return (memcmp(&a->addr.v6, &b->addr.v6,
				sizeof(a->addr.v6)) == 0);
	return (0);
}

/**
 * @brief Convert a scanner IP address to printable presentation form.
 */
int	nmap_ip_ntop(const t_nmap_ip_addr *addr, char *dst, size_t dst_size)
{
	const void	*src;

	if (!addr || !dst || dst_size == 0)
		return (0);
	if (addr->family == AF_INET)
		src = &addr->addr.v4;
	else if (addr->family == AF_INET6)
		src = &addr->addr.v6;
	else
		return (0);
	return (inet_ntop(addr->family, src, dst, dst_size) != NULL);
}
