#ifndef NMAP_OUTPUT_INTERNAL_H
# define NMAP_OUTPUT_INTERNAL_H

# include "output/output.h"

# include <stddef.h>
# include <stdint.h>

# define NMAP_OUTPUT_SERVICE_WIDTH 16
# define NMAP_OUTPUT_STATE_WIDTH 5
# define NMAP_OUTPUT_REASON_WIDTH 15
# define NMAP_OUTPUT_VERDICT_WIDTH 18
# define NMAP_OUTPUT_SERVICE_MAX 64

/**
 * @brief Aggregate conclusion produced by the output layer.
 *
 * A probe result belongs to one concrete scan. A port verdict may aggregate
 * several already-classified probes, so MIXED exists only at this layer.
 */
typedef enum e_nmap_port_verdict
{
	NMAP_VERDICT_NONE = 0,
	NMAP_VERDICT_OPEN,
	NMAP_VERDICT_CLOSED,
	NMAP_VERDICT_FILTERED,
	NMAP_VERDICT_UNFILTERED,
	NMAP_VERDICT_OPEN_FILTERED,
	NMAP_VERDICT_MIXED,
	NMAP_VERDICT_ERROR
}	t_nmap_port_verdict;

/**
 * @brief Read-only view of every scan result associated with one port.
 *
 * The output layer does not own these probes. All pointers refer to the
 * current target runtime and remain valid until target cleanup.
 */
typedef struct s_nmap_port_view
{
	uint16_t			port;

	const t_probe		*syn;
	const t_probe		*null_scan;
	const t_probe		*fin;
	const t_probe		*xmas;
	const t_probe		*ack;
	const t_probe		*udp;

	t_nmap_port_verdict	tcp_verdict;
	t_nmap_port_verdict	udp_verdict;
}	t_nmap_port_view;

/* port view / verdict */
void		nmap_output_build_port_view(const t_nmap_config *config,
				uint16_t port, t_nmap_port_view *view);
int			nmap_output_view_is_open_like(const t_nmap_port_view *view);

/* formatting */
const char	*nmap_output_state_name(const t_probe *probe);
void		nmap_output_reason_name(const t_probe *probe,
				char *dst, size_t dst_size);
const char	*nmap_output_verdict_name(t_nmap_port_verdict verdict);
void		nmap_output_format_duration(uint64_t elapsed_ms,
				char *dst, size_t dst_size);
void		nmap_output_format_hms(uint64_t elapsed_ms,
				char *dst, size_t dst_size);

/* colors */
int			nmap_output_color_enabled(void);
const char	*nmap_output_state_color(const t_probe *probe);
const char	*nmap_output_verdict_color(t_nmap_port_verdict verdict);
const char	*nmap_output_color_reset(void);

/* service name */
void		nmap_output_service_name(const t_nmap_port_view *view,
				char *dst, size_t dst_size);

#endif
