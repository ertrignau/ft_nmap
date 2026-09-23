#include "runtime/runtime_internal.h"
#include "net/address.h"

#include <netinet/in.h>

/**
 * @brief Validate a direct TCP/UDP reply against one candidate probe.
 */
static int	direct_reply_matches(const t_nmap_target_ctx *ctx,
		const t_probe *probe, const t_nmap_reply *reply)
{
	if (!nmap_ip_equal(&reply->src_addr, &ctx->target.addr)
		|| !nmap_ip_equal(&reply->dst_addr, &ctx->route.src_addr)
		|| reply->src_port != probe->dst_port
		|| reply->dst_port != probe->src_port)
		return (0);
	if (reply->type == NMAP_REPLY_TCP && probe->scan_type != NMAP_SCAN_UDP)
		return (1);
	if (reply->type == NMAP_REPLY_UDP && probe->scan_type == NMAP_SCAN_UDP)
		return (1);
	return (0);
}

/**
 * @brief Validate an ICMPv4/ICMPv6 error against its quoted original probe.
 *
 * @note The outer ICMP sender is intentionally not required to be the target:
 *       routers/firewalls may legitimately generate filtered/unreachable
 *       errors. Classification later uses the outer sender where semantics
 *       depend on whether the target itself emitted the message.
 */
static int	icmp_reply_matches(const t_nmap_target_ctx *ctx,
		const t_probe *probe, const t_nmap_reply *reply)
{
	if (!nmap_ip_equal(&reply->dst_addr, &ctx->route.src_addr)
		|| !nmap_ip_equal(&reply->original_src_addr, &ctx->route.src_addr)
		|| !nmap_ip_equal(&reply->original_dst_addr, &ctx->target.addr)
		|| reply->original_src_port != probe->src_port
		|| reply->original_dst_port != probe->dst_port)
		return (0);
	if (probe->scan_type == NMAP_SCAN_UDP)
		return (reply->original_protocol == IPPROTO_UDP);
	if (reply->original_protocol != IPPROTO_TCP)
		return (0);
	if (reply->has_original_tcp_seq
		&& reply->original_tcp_seq != probe->seq)
		return (0);
	return (1);
}

/** Extract the O(1) source-port lookup key carried by one reply. */
static int	reply_index_key(const t_nmap_reply *reply, uint16_t *key)
{
	if (reply->type == NMAP_REPLY_TCP || reply->type == NMAP_REPLY_UDP)
	{
		*key = reply->dst_port;
		return (1);
	}
	if (reply->type == NMAP_REPLY_ICMP4 || reply->type == NMAP_REPLY_ICMP6)
	{
		*key = reply->original_src_port;
		return (1);
	}
	return (0);
}

/**
 * @brief Find the logical probe corresponding to one parsed reply.
 *
 * @return Matching probe or NULL when the packet must be ignored.
 *
 * @note Lookup is O(1), but no packet is trusted from source-port identity
 *       alone. All protocol/address/port fields are validated afterwards.
 */
t_probe	*nmap_find_matching_probe(t_nmap_target_ctx *ctx, t_nmap_reply *reply)
{
	t_probe		*probe;
	uint16_t	key;
	int			matches;

	if (!ctx || !reply || !reply_index_key(reply, &key))
		return (NULL);
	pthread_mutex_lock(&ctx->runtime.lock);
	probe = ctx->runtime.probe_by_src_port[key];
	matches = nmap_probe_can_match(probe);
	if (matches && (reply->type == NMAP_REPLY_TCP
			|| reply->type == NMAP_REPLY_UDP))
		matches = direct_reply_matches(ctx, probe, reply);
	else if (matches && (reply->type == NMAP_REPLY_ICMP4
			|| reply->type == NMAP_REPLY_ICMP6))
		matches = icmp_reply_matches(ctx, probe, reply);
	else
	{
		matches = 0;
	}
	pthread_mutex_unlock(&ctx->runtime.lock);
	if (!matches)
		return (NULL);
	return (probe);
}
