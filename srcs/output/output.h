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

/** Print effective scan configuration before one target scan. */
void	nmap_output_begin_scan(const t_nmap_config *config);

/** Print one user-requested immutable progress snapshot. */
void	nmap_output_print_progress(const t_nmap_progress *progress);

/** Print the completed report for one target. */
void	nmap_output_print_target_report(const t_nmap_config *config,
			uint64_t elapsed_ms, int multi_target);

/** Print the process-level summary after all targets were handled. */
void	nmap_output_print_run_summary(size_t total_targets,
			size_t completed_targets, uint64_t elapsed_ms);

#endif
