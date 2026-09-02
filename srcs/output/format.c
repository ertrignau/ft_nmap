#include "output/output_internal.h"
#include "packet/wire.h"

#include <stdio.h>
#include <unistd.h>

#define ANSI_RESET "\033[0m"
#define ANSI_GREEN "\033[32m"
#define ANSI_RED "\033[31m"
#define ANSI_YELLOW "\033[33m"
#define ANSI_CYAN "\033[36m"
#define ANSI_MAGENTA "\033[35m"

/** Return the compact state token used inside one scan column. */
const char	*nmap_output_state_name(const t_probe *probe)
{
	if (!probe)
		return ("-");
	if (probe->state != PROBE_DONE
		|| probe->result == SCAN_RESULT_UNKNOWN)
		return ("ERR");
	if (probe->result == SCAN_RESULT_OPEN)
		return ("OPN");
	if (probe->result == SCAN_RESULT_CLOSED)
		return ("CLS");
	if (probe->result == SCAN_RESULT_FILTERED)
		return ("FLT");
	if (probe->result == SCAN_RESULT_UNFILTERED)
		return ("UNF");
	if (probe->result == SCAN_RESULT_OPEN_FILTERED)
		return ("O|F");
	return ("ERR");
}

/** Format one ICMPv4 reason using a stable, concise vocabulary. */
static void	format_icmp4_reason(const t_scan_reason *reason,
		char *dst, size_t dst_size)
{
	if (reason->icmp_type == 3 && reason->icmp_code == 0)
		snprintf(dst, dst_size, "net-unreach");
	else if (reason->icmp_type == 3 && reason->icmp_code == 1)
		snprintf(dst, dst_size, "host-unreach");
	else if (reason->icmp_type == 3 && reason->icmp_code == 2)
		snprintf(dst, dst_size, "proto-unreach");
	else if (reason->icmp_type == 3 && reason->icmp_code == 3)
		snprintf(dst, dst_size, "port-unreach");
	else if (reason->icmp_type == 3 && reason->icmp_code == 9)
		snprintf(dst, dst_size, "net-prohibit");
	else if (reason->icmp_type == 3 && reason->icmp_code == 10)
		snprintf(dst, dst_size, "host-prohibit");
	else if (reason->icmp_type == 3 && reason->icmp_code == 13)
		snprintf(dst, dst_size, "admin-prohibit");
	else if (reason->icmp_type == 11 && reason->icmp_code == 0)
		snprintf(dst, dst_size, "ttl-exceeded");
	else if (reason->icmp_type == 11 && reason->icmp_code == 1)
		snprintf(dst, dst_size, "frag-timeout");
	else
		snprintf(dst, dst_size, "icmp4-%u/%u",
			reason->icmp_type, reason->icmp_code);
}

/** Format one ICMPv6 reason using a stable, concise vocabulary. */
static void	format_icmp6_reason(const t_scan_reason *reason,
		char *dst, size_t dst_size)
{
	if (reason->icmp_type == 1 && reason->icmp_code == 0)
		snprintf(dst, dst_size, "no-route");
	else if (reason->icmp_type == 1 && reason->icmp_code == 1)
		snprintf(dst, dst_size, "admin-prohibit");
	else if (reason->icmp_type == 1 && reason->icmp_code == 2)
		snprintf(dst, dst_size, "beyond-scope");
	else if (reason->icmp_type == 1 && reason->icmp_code == 3)
		snprintf(dst, dst_size, "addr-unreach");
	else if (reason->icmp_type == 1 && reason->icmp_code == 4)
		snprintf(dst, dst_size, "port-unreach");
	else if (reason->icmp_type == 1 && reason->icmp_code == 5)
		snprintf(dst, dst_size, "src-policy");
	else if (reason->icmp_type == 1 && reason->icmp_code == 6)
		snprintf(dst, dst_size, "reject-route");
	else if (reason->icmp_type == 3 && reason->icmp_code == 0)
		snprintf(dst, dst_size, "hop-exceeded");
	else if (reason->icmp_type == 3 && reason->icmp_code == 1)
		snprintf(dst, dst_size, "frag-timeout");
	else
		snprintf(dst, dst_size, "icmp6-%u/%u",
			reason->icmp_type, reason->icmp_code);
}

/**
 * @brief Format one structured runtime reason.
 *
 * Every invocation formats the reason of exactly one concrete scan probe.
 * Reasons from different scans are never merged.
 */
void	nmap_output_reason_name(const t_probe *probe,
		char *dst, size_t dst_size)
{
	const t_scan_reason	*reason;

	if (!dst || dst_size == 0)
		return ;
	if (!probe)
	{
		snprintf(dst, dst_size, "-");
		return ;
	}
	reason = &probe->reason;
	if (reason->kind == SCAN_REASON_TCP)
	{
		if ((reason->tcp_flags & NMAP_TCP_SYN)
			&& (reason->tcp_flags & NMAP_TCP_ACK))
			snprintf(dst, dst_size, "syn-ack");
		else if (reason->tcp_flags & NMAP_TCP_RST)
			snprintf(dst, dst_size, "reset");
		else if (reason->tcp_flags & NMAP_TCP_SYN)
			snprintf(dst, dst_size, "syn");
		else
			snprintf(dst, dst_size, "tcp-0x%02x",
				reason->tcp_flags);
	}
	else if (reason->kind == SCAN_REASON_UDP_REPLY)
		snprintf(dst, dst_size, "udp-reply");
	else if (reason->kind == SCAN_REASON_NO_RESPONSE)
		snprintf(dst, dst_size, "no-response");
	else if (reason->kind == SCAN_REASON_SEND_ERROR)
		snprintf(dst, dst_size, "send-error");
	else if (reason->kind == SCAN_REASON_ICMP
		&& reason->family == AF_INET)
		format_icmp4_reason(reason, dst, dst_size);
	else if (reason->kind == SCAN_REASON_ICMP
		&& reason->family == AF_INET6)
		format_icmp6_reason(reason, dst, dst_size);
	else
		snprintf(dst, dst_size, "-");
}

/** Return the compact representation of one aggregate verdict. */
const char	*nmap_output_verdict_name(t_nmap_port_verdict verdict)
{
	if (verdict == NMAP_VERDICT_OPEN)
		return ("OPN");
	if (verdict == NMAP_VERDICT_CLOSED)
		return ("CLS");
	if (verdict == NMAP_VERDICT_FILTERED)
		return ("FLT");
	if (verdict == NMAP_VERDICT_UNFILTERED)
		return ("UNF");
	if (verdict == NMAP_VERDICT_OPEN_FILTERED)
		return ("O|F");
	if (verdict == NMAP_VERDICT_MIXED)
		return ("MIX");
	if (verdict == NMAP_VERDICT_ERROR)
		return ("ERR");
	return ("-");
}

/** Format a monotonic elapsed duration with millisecond precision. */
void	nmap_output_format_duration(uint64_t elapsed_ms,
		char *dst, size_t dst_size)
{
	if (!dst || dst_size == 0)
		return ;
	snprintf(dst, dst_size, "%llu.%03llus",
		(unsigned long long)(elapsed_ms / 1000ULL),
		(unsigned long long)(elapsed_ms % 1000ULL));
}

/**
 * @brief Return whether ANSI colors are suitable for stdout.
 *
 * Redirected output remains plain text.
 */
int	nmap_output_color_enabled(void)
{
	return (isatty(STDOUT_FILENO) != 0);
}

/** Return the ANSI color associated with one concrete scan result. */
const char	*nmap_output_state_color(const t_probe *probe)
{
	if (!probe || probe->state != PROBE_DONE
		|| probe->result == SCAN_RESULT_UNKNOWN)
		return (ANSI_RED);
	if (probe->result == SCAN_RESULT_OPEN)
		return (ANSI_GREEN);
	if (probe->result == SCAN_RESULT_CLOSED)
		return (ANSI_RED);
	if (probe->result == SCAN_RESULT_FILTERED
		|| probe->result == SCAN_RESULT_OPEN_FILTERED)
		return (ANSI_YELLOW);
	if (probe->result == SCAN_RESULT_UNFILTERED)
		return (ANSI_CYAN);
	return (ANSI_RED);
}

/** Return the ANSI color associated with an aggregate verdict. */
const char	*nmap_output_verdict_color(t_nmap_port_verdict verdict)
{
	if (verdict == NMAP_VERDICT_OPEN)
		return (ANSI_GREEN);
	if (verdict == NMAP_VERDICT_CLOSED
		|| verdict == NMAP_VERDICT_ERROR)
		return (ANSI_RED);
	if (verdict == NMAP_VERDICT_FILTERED
		|| verdict == NMAP_VERDICT_OPEN_FILTERED)
		return (ANSI_YELLOW);
	if (verdict == NMAP_VERDICT_UNFILTERED)
		return (ANSI_CYAN);
	if (verdict == NMAP_VERDICT_MIXED)
		return (ANSI_MAGENTA);
	return ("");
}

const char	*nmap_output_color_reset(void)
{
	return (ANSI_RESET);
}