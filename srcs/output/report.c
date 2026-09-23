#include "output/output_internal.h"

#include <stdio.h>
#include <string.h>

/**
 * @brief Return whether one scan family is enabled.
 */
static int	scan_enabled(const t_nmap_target_ctx *ctx, uint32_t scan)
{
	return ((ctx->scan->scan_mask & scan) != 0);
}

/**
 * @brief Print one fixed-width token and color only its visible contents.
 *
 * Padding remains outside the ANSI sequence so redirected/plain rendering and
 * visual column widths stay predictable.
 */
static void	print_colored_token(const char *token, const char *color,
		int width, int use_color)
{
	if (use_color && color && color[0] != '\0')
		printf("%s%s%s%-*s", color, token,
			nmap_output_color_reset(),
			width - (int)strlen(token), "");
	else
	{
		printf("%-*s", width, token);
	}
}

/** Print one scan state column. */
static void	print_state_cell(const t_probe *probe, int use_color)
{
	const char	*state;

	state = nmap_output_state_name(probe);
	print_colored_token(state, nmap_output_state_color(probe),
		NMAP_OUTPUT_STATE_WIDTH,
		use_color && probe != NULL);
}

/** Print the dedicated reason column associated with one scan. */
static void	print_reason_cell(const t_probe *probe)
{
	char	reason[64];

	nmap_output_reason_name(probe, reason, sizeof(reason));
	printf("%-*s", NMAP_OUTPUT_REASON_WIDTH, reason);
}

/**
 * @brief Print one scan result.
 *
 * With --reason, the state and its reason deliberately occupy two independent
 * table columns.
 */
static void	print_scan_cell(const t_probe *probe, int show_reason,
		int use_color)
{
	print_state_cell(probe, use_color);
	if (show_reason)
		print_reason_cell(probe);
}

/** Print the state/reason header pair for one scan family. */
static void	print_scan_header(const char *scan_name, int show_reason)
{
	char	reason_header[32];

	printf("%-*s", NMAP_OUTPUT_STATE_WIDTH, scan_name);
	if (show_reason)
	{
		snprintf(reason_header, sizeof(reason_header),
			"%s-REASON", scan_name);
		printf("%-*s", NMAP_OUTPUT_REASON_WIDTH,
			reason_header);
	}
}

/** Print only the columns corresponding to enabled scan families. */
static void	print_table_header(const t_nmap_target_ctx *ctx)
{
	printf("%-7s%-*s", "PORT",
		NMAP_OUTPUT_SERVICE_WIDTH, "SERVICE");
	if (scan_enabled(ctx, NMAP_SCAN_SYN))
		print_scan_header("SYN", ctx->scan->show_reason);
	if (scan_enabled(ctx, NMAP_SCAN_NULL))
		print_scan_header("NUL", ctx->scan->show_reason);
	if (scan_enabled(ctx, NMAP_SCAN_FIN))
		print_scan_header("FIN", ctx->scan->show_reason);
	if (scan_enabled(ctx, NMAP_SCAN_XMAS))
		print_scan_header("XMS", ctx->scan->show_reason);
	if (scan_enabled(ctx, NMAP_SCAN_ACK))
		print_scan_header("ACK", ctx->scan->show_reason);
	if (scan_enabled(ctx, NMAP_SCAN_UDP))
		print_scan_header("UDP", ctx->scan->show_reason);
	printf("%s\n", "VERDICT");
}

/** Print one colored verdict token without adding padding. */
static void	print_inline_token(const char *token, const char *color,
		int use_color)
{
	if (use_color && color && color[0] != '\0')
		printf("%s%s%s", color, token,
			nmap_output_color_reset());
	else
	{
		printf("%s", token);
	}
}

/**
 * @brief Print TCP and UDP conclusions independently.
 *
 * Each protocol keeps its own color. For example, T:CLS U:OPN must not become
 * globally green because TCP/53 and UDP/53 are different endpoints.
 */
static void	print_verdict_cell(const t_nmap_port_view *view,
		int use_color)
{
	const char	*tcp;
	const char	*udp;
	int			visible_len;

	tcp = nmap_output_verdict_name(view->tcp_verdict);
	udp = nmap_output_verdict_name(view->udp_verdict);
	visible_len = 0;
	if (view->tcp_verdict != NMAP_VERDICT_NONE
		&& view->udp_verdict != NMAP_VERDICT_NONE)
	{
		printf("T:");
		print_inline_token(tcp,
			nmap_output_verdict_color(view->tcp_verdict),
			use_color);
		printf(" U:");
		print_inline_token(udp,
			nmap_output_verdict_color(view->udp_verdict),
			use_color);
		visible_len = 5 + (int)strlen(tcp)
			+ (int)strlen(udp);
	}
	else if (view->tcp_verdict != NMAP_VERDICT_NONE)
	{
		print_inline_token(tcp,
			nmap_output_verdict_color(view->tcp_verdict),
			use_color);
		visible_len = (int)strlen(tcp);
	}
	else if (view->udp_verdict != NMAP_VERDICT_NONE)
	{
		print_inline_token(udp,
			nmap_output_verdict_color(view->udp_verdict),
			use_color);
		visible_len = (int)strlen(udp);
	}
	else
	{
		printf("-");
		visible_len = 1;
	}
	if (visible_len < NMAP_OUTPUT_VERDICT_WIDTH)
		printf("%*s",
			NMAP_OUTPUT_VERDICT_WIDTH - visible_len, "");
}

/** Print one complete port row. */
static void	print_port_row(const t_nmap_target_ctx *ctx,
		const t_nmap_port_view *view, int use_color)
{
	char	service[NMAP_OUTPUT_SERVICE_MAX];

	nmap_output_service_name(view, service, sizeof(service));
	printf("%-7u%-*.*s",
		view->port,
		NMAP_OUTPUT_SERVICE_WIDTH,
		NMAP_OUTPUT_SERVICE_WIDTH - 1,
		service);
	if (scan_enabled(ctx, NMAP_SCAN_SYN))
		print_scan_cell(view->syn,
			ctx->scan->show_reason, use_color);
	if (scan_enabled(ctx, NMAP_SCAN_NULL))
		print_scan_cell(view->null_scan,
			ctx->scan->show_reason, use_color);
	if (scan_enabled(ctx, NMAP_SCAN_FIN))
		print_scan_cell(view->fin,
			ctx->scan->show_reason, use_color);
	if (scan_enabled(ctx, NMAP_SCAN_XMAS))
		print_scan_cell(view->xmas,
			ctx->scan->show_reason, use_color);
	if (scan_enabled(ctx, NMAP_SCAN_ACK))
		print_scan_cell(view->ack,
			ctx->scan->show_reason, use_color);
	if (scan_enabled(ctx, NMAP_SCAN_UDP))
		print_scan_cell(view->udp,
			ctx->scan->show_reason, use_color);
	print_verdict_cell(view, use_color);
	printf("\n");
}

/**
 * --short keeps evidence, not every inconclusive result. Unlike Nmap's
 * normal display, standalone open|filtered rows are always suppressed as
 * explicitly requested. Closed rows are kept when they are in the minority.
 * No scan result is changed: this policy belongs exclusively to output.
 */
typedef enum e_short_row
{
    SHORT_VISIBLE,
    SHORT_CLOSED,
    SHORT_NO_RESPONSE,
    SHORT_OPEN_FILTERED,
    SHORT_ACK_UNFILTERED
}   t_short_row;

/** Return 1 only for a finalized probe with the requested result. */
static int  probe_is(const t_probe *probe, t_scan_result result)
{
    return (probe && probe->state == PROBE_DONE
        && probe->result == result);
}

/** Explicit ICMP errors, including router-originated ones, are evidence. */
static int  explicit_filter(const t_probe *probe)
{
    return (probe_is(probe, SCAN_RESULT_FILTERED)
        && probe->reason.kind == SCAN_REASON_ICMP);
}

/** Filter one whole row, never separate scan columns of that same port. */
static t_short_row  classify_short_row(const t_nmap_port_view *view)
{
    const t_probe *p[6];
    size_t          i;
    int             closed;
    int             open_filtered;
    int             silent_filtered;
    int             unfiltered;

    p[0] = view->syn;
    p[1] = view->null_scan;
    p[2] = view->fin;
    p[3] = view->xmas;
    p[4] = view->ack;
    p[5] = view->udp;
    closed = 0;
    open_filtered = 0;
    silent_filtered = 0;
    unfiltered = 0;
    /* A distinct SYN/ACK firewall behavior is worth showing. */
    if (probe_is(view->syn, SCAN_RESULT_FILTERED)
        && probe_is(view->ack, SCAN_RESULT_UNFILTERED))
        return (SHORT_VISIBLE);
    i = 0;
    while (i < 6)
    {
        if (p[i] && (p[i]->state != PROBE_DONE
                || p[i]->result == SCAN_RESULT_UNKNOWN))
            return (SHORT_VISIBLE);
        if (probe_is(p[i], SCAN_RESULT_OPEN)
            || explicit_filter(p[i]))
            return (SHORT_VISIBLE);
        if (probe_is(p[i], SCAN_RESULT_CLOSED))
            closed = 1;
        if (probe_is(p[i], SCAN_RESULT_OPEN_FILTERED))
            open_filtered = 1;
        if (probe_is(p[i], SCAN_RESULT_FILTERED))
            silent_filtered = 1;
        if (probe_is(p[i], SCAN_RESULT_UNFILTERED))
            unfiltered = 1;
        i++;
    }
    /* A closed port plus filtering on a different scan is notable. */
    if (closed && silent_filtered)
        return (SHORT_VISIBLE);
    if (closed)
        return (SHORT_CLOSED);
    if (open_filtered)
        return (SHORT_OPEN_FILTERED);
    if (silent_filtered)
        return (SHORT_NO_RESPONSE);
    if (unfiltered)
        return (SHORT_ACK_UNFILTERED);
    return (SHORT_VISIBLE);
}

/**
 * Nmap hides the prevalent non-open state, not every closed port. Here we
 * collapse repetitive closed rows when they cover a strict majority; rare
 * closed ports remain visible among filtered or open results.
 */
static size_t  count_closed_rows(const t_nmap_target_ctx *ctx)
{
    t_nmap_port_view  view;
    size_t            i;
    size_t            closed;

    closed = 0;
    i = 0;
    while (i < ctx->scan->port_count)
    {
        nmap_output_build_port_view(ctx, ctx->scan->ports[i], &view);
        if (classify_short_row(&view) == SHORT_CLOSED)
            closed++;
        i++;
    }
    return (closed);
}

/** Print the selected rows and explain exactly what was condensed. */
static void print_result_table(const t_nmap_target_ctx *ctx)
{
    t_nmap_port_view view;
    size_t           hidden[5];
    size_t           closed_rows;
    size_t           shown;
    size_t           i;
    t_short_row      row;
    int              use_color;

    use_color = nmap_output_color_enabled();
    closed_rows = 0;
    memset(hidden, 0, sizeof(hidden));
    if (ctx->scan->short_output)
        closed_rows = count_closed_rows(ctx);
    shown = 0;
    print_table_header(ctx);
    i = 0;
    while (i < ctx->scan->port_count)
    {
        nmap_output_build_port_view(ctx, ctx->scan->ports[i], &view);
        row = SHORT_VISIBLE;
        if (ctx->scan->short_output)
        {
            row = classify_short_row(&view);
            if (row == SHORT_CLOSED
                && closed_rows * 2 <= ctx->scan->port_count)
                row = SHORT_VISIBLE;
        }
        if (row == SHORT_VISIBLE)
        {
            print_port_row(ctx, &view, use_color);
            shown++;
        }
        else
            hidden[row]++;
        i++;
    }
    if (ctx->scan->short_output)
    {
        i = hidden[SHORT_CLOSED] + hidden[SHORT_NO_RESPONSE]
            + hidden[SHORT_OPEN_FILTERED] + hidden[SHORT_ACK_UNFILTERED];
        if (i > 0)
            printf("Not shown: %zu ports (common closed: %zu, "
                "silent filtered: %zu, open|filtered: %zu, "
                "ACK-only unfiltered: %zu)\n", i, hidden[SHORT_CLOSED],
                hidden[SHORT_NO_RESPONSE], hidden[SHORT_OPEN_FILTERED],
                hidden[SHORT_ACK_UNFILTERED]);
        if (shown == 0)
            puts("No port rows to display in --short mode.");
    }
}

/** Print the compact report-state legend. */
void	nmap_output_print_results_legend(void)
{
	printf("\n");
	printf("Legend: "
		"OPN=open  "
		"CLS=closed  "
		"FLT=filtered  "
		"UNF=unfiltered  "
		"O|F=open|filtered  "
		"MIX=mixed  "
		"ERR=error\n");
}

/** Print the best available target identity. */
static void	print_target_identity(const t_nmap_target_ctx *ctx)
{
	if (ctx->target.hostname[0] != '\0'
		&& strcmp(ctx->target.hostname, ctx->target.ip) != 0)
	{
		printf("ft_nmap scan report for %s (%s)\n",
			ctx->target.hostname, ctx->target.ip);
		return ;
	}
	if (ctx->target.name
		&& strcmp(ctx->target.name, ctx->target.ip) != 0)
	{
		printf("ft_nmap scan report for %s (%s)\n",
			ctx->target.name, ctx->target.ip);
		return ;
	}
	printf("ft_nmap scan report for %s\n", ctx->target.ip);
}

/** Return the deliberately broad OS family associated with one TTL bucket. */
static const char	*os_guess_name(uint8_t initial_hop_limit)
{
	if (initial_hop_limit == 64)
		return ("Unix/Linux-like");
	if (initial_hop_limit == 128)
		return ("Windows-like");
	if (initial_hop_limit == 255)
		return ("Network/Unix-like");
	return ("unknown");
}

/**
 * @brief Print lightweight OS detection based on TTL/Hop Limit.
 *
 * This is deliberately labelled as a guess: many systems can customize their
 * initial TTL and several operating systems share the same conventional value.
 */
static void	print_os_guess(const t_nmap_target_ctx *ctx)
{
	const char	*label;

	if (!ctx->scan->os_detection)
		return ;
	if (ctx->target.observed_hop_limit == 0
		|| ctx->target.initial_hop_limit == 0)
	{
		printf("OS guess : unavailable (no direct target reply)\n");
		return ;
	}
	label = os_guess_name(ctx->target.initial_hop_limit);
	if (ctx->target.addr.family == AF_INET6)
	{
		printf("OS guess : %s "
			"(Hop Limit observed %u, initial ~%u)\n",
			label,
			(unsigned int)ctx->target.observed_hop_limit,
			(unsigned int)ctx->target.initial_hop_limit);
	}
	else
	{
		printf("OS guess : %s "
			"(TTL observed %u, initial ~%u)\n",
			label,
			(unsigned int)ctx->target.observed_hop_limit,
			(unsigned int)ctx->target.initial_hop_limit);
	}
}

/** Result tables are presented after the global scan, in input order. */
void nmap_output_print_target_report(const t_nmap_target_ctx *ctx)
{
    if (!ctx)
        return ;
    print_target_identity(ctx);
    print_os_guess(ctx);
    putchar('\n');
    print_result_table(ctx);
    putchar('\n');
}

/** The only elapsed time displayed is the wall time of the complete scan. */
void nmap_output_print_run_summary(size_t total_targets,
        size_t completed_targets, uint64_t elapsed_ms)
{
    char duration[32];

    nmap_output_format_duration(elapsed_ms, duration, sizeof(duration));
    puts("=============== SUMMARY ===============");
    printf("Targets   : %zu/%zu completed\n", completed_targets, total_targets);
    if (completed_targets < total_targets)
        printf("Unfinished/failed : %zu\n", total_targets - completed_targets);
    printf("Total scan time : %s\n", duration);
    puts("=======================================");
}
