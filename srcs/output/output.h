#ifndef NMAP_OUTPUT_H
# define NMAP_OUTPUT_H

# include "config.h"

# include <stddef.h>
# include <stdint.h>

/**
 * @brief Immutable runtime progress snapshot consumed by the output layer.
 *
 * The output module owns presentation only. It never locks or reads mutable
 * runtime state directly.
 */
typedef struct s_nmap_progress
{
	size_t		total;
	size_t		done;
	size_t		queued;
	size_t		outstanding;
	size_t		benched;
	size_t		pending;
	uint64_t	elapsed_ms;
}	t_nmap_progress;

/** Immutable snapshot of a single destination's progress. */
typedef struct s_nmap_target_progress
{
    const char           *name;
    unsigned int         ifindex;
    t_nmap_target_status status;
    size_t               total;
    size_t               done;
    size_t               queued;
    size_t               outstanding;
    size_t               benched;
}   t_nmap_target_progress;

/** One prepared, immutable banner grouped by outgoing interface. */
void    nmap_output_print_scan_banner(const t_nmap_engine *engine);

/** Enter: one global progress line and a per-destination table. */
void    nmap_output_print_target_progress(const t_nmap_progress *global,
            const t_nmap_target_progress *targets, size_t target_count,
            const t_nmap_iface_ctx *ifaces, size_t iface_count,
            size_t completed_targets, size_t expected_targets);

/** One completed target's results; no per-target duration. */
void    nmap_output_print_target_report(const t_nmap_target_ctx *ctx);

/** Print common legend once, after the ordered reports. */
void    nmap_output_print_results_legend(void);

/** One global scan duration, including the single-target case. */
void    nmap_output_print_run_summary(size_t total_targets,
            size_t completed_targets, uint64_t elapsed_ms);

#endif
