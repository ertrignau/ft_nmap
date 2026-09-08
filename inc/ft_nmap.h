#ifndef FT_NMAP_H
# define FT_NMAP_H

# include "config.h"

/* config */
int		nmap_init_config(t_nmap_config *config, const char *program_name,
			int *exit_status);
int		nmap_prepare_scan_config(t_nmap_config *config, int *exit_status);
int		nmap_prepare_targets(t_nmap_config *config, int *exit_status);
void	nmap_cleanup_current_target(t_nmap_config *config);
void	nmap_cleanup_config(t_nmap_config *config);

/* target / network */
int		nmap_prepare_target(t_nmap_config *config, const char *target_name,
			int *exit_status);
int		nmap_prepare_route(t_nmap_config *config, int *exit_status);
int		nmap_prepare_send_socket(t_nmap_config *config, int *exit_status);
int		nmap_prepare_pcap(t_nmap_config *config, int *exit_status);

/* run */
int		nmap_run(t_nmap_config *config, int *exit_status);

/* runtime */
int		nmap_prepare_runtime(t_nmap_config *config, int *exit_status);
int		nmap_runtime_is_finished(t_nmap_config *config);
int		nmap_runtime_drain_replies(t_nmap_config *config, int *exit_status);
void	nmap_runtime_expire_probes(t_nmap_config *config);
int		nmap_runtime_schedule_ready(t_nmap_config *config, int *exit_status);
int		nmap_runtime_wait(t_nmap_config *config, int *exit_status);
int		nmap_prepare_sender_pool(t_nmap_config *config, int *exit_status);
void	nmap_stop_sender_pool(t_nmap_config *config);
int		nmap_sender_pool_has_error(t_nmap_config *config);

/* output */
void	nmap_output_print_target_report(const t_nmap_config *config,
			uint64_t elapsed_ms, int multi_target);
void	nmap_output_print_run_summary(size_t total_targets,
			size_t completed_targets, uint64_t elapsed_ms);

/* parsing */
int		nmap_parse_ports(t_nmap_config *config, const char *arg);
int		parse_flag(t_nmap_config *config, int argc, char **argv, int *i);
int		parse_ip(t_nmap_config *config, int argc, char **argv, int *i);
int		parse_port(t_nmap_config *config, int argc, char **argv, int *i);
int		parse_scan(t_nmap_config *config, int argc, char **argv, int *i);
int		parse_speedup(t_nmap_config *config, int argc, char **argv, int *i);
int		parse_timeout(t_nmap_config *config, int argc, char **argv, int *i);
int		parse_retries(t_nmap_config *config, int argc, char **argv, int *i);
int		parse_file(t_nmap_config *config, int argc, char **argv, int *i);
int		parse_bool_flag(t_nmap_config *config, const char *flag);
int		nmap_parse_cli(t_nmap_config *config, int argc, char **argv,
			int *exit_status);

/* parsing utils */
int		nmap_streq(const char *a, const char *b);
int		nmap_parse_int(const char *s, int *out);

/* signal */
int		nmap_signal_setup(int *exit_status);
int		nmap_signal_stop_requested(void);

#endif
