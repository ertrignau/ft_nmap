#include "output/output_internal.h"

#include <string.h>

/** Return whether one scan type belongs to the TCP family. */
static int	is_tcp_scan(uint32_t scan_type)
{
	return (scan_type == NMAP_SCAN_SYN
		|| scan_type == NMAP_SCAN_NULL
		|| scan_type == NMAP_SCAN_FIN
		|| scan_type == NMAP_SCAN_XMAS
		|| scan_type == NMAP_SCAN_ACK);
}

/** Attach one runtime probe to its slot in a read-only port view. */
static void	attach_probe(t_nmap_port_view *view, const t_probe *probe)
{
	if (probe->scan_type == NMAP_SCAN_SYN)
		view->syn = probe;
	else if (probe->scan_type == NMAP_SCAN_NULL)
		view->null_scan = probe;
	else if (probe->scan_type == NMAP_SCAN_FIN)
		view->fin = probe;
	else if (probe->scan_type == NMAP_SCAN_XMAS)
		view->xmas = probe;
	else if (probe->scan_type == NMAP_SCAN_ACK)
		view->ack = probe;
	else if (probe->scan_type == NMAP_SCAN_UDP)
		view->udp = probe;
}

/**
 * @brief Record one final TCP result in aggregate evidence flags.
 *
 * flags:
 *   0 = OPEN
 *   1 = CLOSED
 *   2 = FILTERED
 *   3 = OPEN|FILTERED
 *   4 = UNFILTERED
 *   5 = ERROR / incomplete
 */
static void	collect_tcp_result(const t_probe *probe, int *flags)
{
	if (!probe)
		return ;
	if (probe->state != PROBE_DONE
		|| probe->result == SCAN_RESULT_UNKNOWN)
	{
		flags[5] = 1;
		return ;
	}
	if (probe->result == SCAN_RESULT_OPEN)
		flags[0] = 1;
	else if (probe->result == SCAN_RESULT_CLOSED)
		flags[1] = 1;
	else if (probe->result == SCAN_RESULT_FILTERED)
		flags[2] = 1;
	else if (probe->result == SCAN_RESULT_OPEN_FILTERED)
		flags[3] = 1;
	else if (probe->result == SCAN_RESULT_UNFILTERED)
		flags[4] = 1;
}

/**
 * @brief Aggregate already-classified TCP observations for one port.
 *
 * OPEN and CLOSED are definitive but contradictory, therefore their
 * coexistence becomes MIXED.
 *
 * FILTERED and OPEN|FILTERED are weaker evidence and never override a
 * definitive OPEN/CLOSED observation.
 *
 * ACK/UNFILTERED is retained only when no stronger port-state evidence exists.
 */
static t_nmap_port_verdict	compute_tcp_verdict(
		const t_nmap_port_view *view)
{
	const t_probe	*probes[5];
	int				flags[6];
	size_t			i;
	int				seen;

	probes[0] = view->syn;
	probes[1] = view->null_scan;
	probes[2] = view->fin;
	probes[3] = view->xmas;
	probes[4] = view->ack;
	memset(flags, 0, sizeof(flags));
	seen = 0;
	i = 0;
	while (i < 5)
	{
		if (probes[i])
		{
			seen = 1;
			collect_tcp_result(probes[i], flags);
		}
		i++;
	}
	if (!seen)
		return (NMAP_VERDICT_NONE);
	if (flags[0] && flags[1])
		return (NMAP_VERDICT_MIXED);
	if (flags[0])
		return (NMAP_VERDICT_OPEN);
	if (flags[1])
		return (NMAP_VERDICT_CLOSED);
	if (flags[2])
		return (NMAP_VERDICT_FILTERED);
	if (flags[3])
		return (NMAP_VERDICT_OPEN_FILTERED);
	if (flags[4])
		return (NMAP_VERDICT_UNFILTERED);
	if (flags[5])
		return (NMAP_VERDICT_ERROR);
	return (NMAP_VERDICT_NONE);
}

/**
 * @brief Convert the single UDP scan result into its protocol verdict.
 *
 * No aggregation is required because there is exactly one UDP scan type.
 */
static t_nmap_port_verdict	compute_udp_verdict(const t_probe *probe)
{
	if (!probe)
		return (NMAP_VERDICT_NONE);
	if (probe->state != PROBE_DONE
		|| probe->result == SCAN_RESULT_UNKNOWN)
		return (NMAP_VERDICT_ERROR);
	if (probe->result == SCAN_RESULT_OPEN)
		return (NMAP_VERDICT_OPEN);
	if (probe->result == SCAN_RESULT_CLOSED)
		return (NMAP_VERDICT_CLOSED);
	if (probe->result == SCAN_RESULT_FILTERED)
		return (NMAP_VERDICT_FILTERED);
	if (probe->result == SCAN_RESULT_OPEN_FILTERED)
		return (NMAP_VERDICT_OPEN_FILTERED);
	return (NMAP_VERDICT_ERROR);
}

/**
 * @brief Build one complete, read-only output view from runtime results.
 *
 * Output deliberately depends only on semantic probe results. It does not
 * parse packets, classify responses or mutate runtime state.
 */
void	nmap_output_build_port_view(const t_nmap_target_ctx *ctx,
		uint16_t port, t_nmap_port_view *view)
{
	size_t	i;

	if (!view)
		return ;
	memset(view, 0, sizeof(*view));
	view->port = port;
	if (!ctx || !ctx->runtime.probes)
		return ;
	i = 0;
	while (i < ctx->runtime.probe_count)
	{
		if (ctx->runtime.probes[i].dst_port == port
			&& (is_tcp_scan(ctx->runtime.probes[i].scan_type)
				|| ctx->runtime.probes[i].scan_type == NMAP_SCAN_UDP))
			attach_probe(view, &ctx->runtime.probes[i]);
		i++;
	}
	view->tcp_verdict = compute_tcp_verdict(view);
	view->udp_verdict = compute_udp_verdict(view->udp);
}
