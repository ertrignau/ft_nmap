#include "output/output_internal.h"

#include <stdio.h>
#include <string.h>

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
		printf("%-*s", width, token);
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

/** Print the stable table header. */
static void	print_table_header(int show_reason)
{
	printf("%-7s%-*s", "PORT",
		NMAP_OUTPUT_SERVICE_WIDTH, "SERVICE");
	print_scan_header("SYN", show_reason);
	print_scan_header("NUL", show_reason);
	print_scan_header("FIN", show_reason);
	print_scan_header("XMS", show_reason);
	print_scan_header("ACK", show_reason);
	print_scan_header("UDP", show_reason);
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
		printf("%s", token);
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
static void	print_port_row(const t_nmap_config *config,
		const t_nmap_port_view *view, int use_color)
{
	char	service[NMAP_OUTPUT_SERVICE_MAX];

	nmap_output_service_name(view, service, sizeof(service));
	printf("%-7u%-*.*s",
		view->port,
		NMAP_OUTPUT_SERVICE_WIDTH,
		NMAP_OUTPUT_SERVICE_WIDTH - 1,
		service);
	print_scan_cell(view->syn,
		config->scan.show_reason, use_color);
	print_scan_cell(view->null_scan,
		config->scan.show_reason, use_color);
	print_scan_cell(view->fin,
		config->scan.show_reason, use_color);
	print_scan_cell(view->xmas,
		config->scan.show_reason, use_color);
	print_scan_cell(view->ack,
		config->scan.show_reason, use_color);
	print_scan_cell(view->udp,
		config->scan.show_reason, use_color);
	print_verdict_cell(view, use_color);
	printf("\n");
}

/** Print every port visible under the current --open policy. */
static void	print_result_table(const t_nmap_config *config)
{
	t_nmap_port_view	view;
	size_t				i;
	int					use_color;

	use_color = nmap_output_color_enabled();
	print_table_header(config->scan.show_reason);
	i = 0;
	while (i < config->scan.port_count)
	{
		nmap_output_build_port_view(config,
			config->scan.ports[i], &view);
		if (!config->scan.open_only
			|| nmap_output_view_is_open_like(&view))
			print_port_row(config, &view, use_color);
		i++;
	}
}

/**
 * @brief Print one successfully completed target.
 *
 * elapsed_ms is measured by run.c. Output owns presentation only.
 */
void	nmap_output_print_target_report(const t_nmap_config *config,
		uint64_t elapsed_ms, int multi_target)
{
	char	duration[32];

	if (!config)
		return ;
	printf("ft_nmap scan report for %s (%s)\n\n",
		config->target.name, config->target.ip);
	print_result_table(config);
	nmap_output_format_duration(elapsed_ms,
		duration, sizeof(duration));
	if (multi_target)
		printf("\nTarget completed in %s\n", duration);
	else
		printf("\nScan completed in %s\n", duration);
}

/** Print the process-level footer for a multi-target run. */
void	nmap_output_print_run_summary(size_t total_targets,
		size_t completed_targets, uint64_t elapsed_ms)
{
	char	duration[32];

	if (total_targets <= 1)
		return ;
	nmap_output_format_duration(elapsed_ms,
		duration, sizeof(duration));
	if (completed_targets == total_targets)
		printf("\nScanned %zu targets in %s\n",
			total_targets, duration);
	else
	{
		printf("\nProcessed %zu targets in %s "
			"(%zu completed, %zu failed)\n",
			total_targets,
			duration,
			completed_targets,
			total_targets - completed_targets);
	}
}