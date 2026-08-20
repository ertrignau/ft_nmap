#ifndef FT_NMAP_H
# define FT_NMAP_H

# include "config.h"

/* config */
int		nmap_load_hardcoded_dev_config(t_nmap_config *config);
void	nmap_cleanup_config(t_nmap_config *config);
void	nmap_cleanup_target_scan(t_nmap_config *config);
int     nmap_init_config(t_nmap_config *config, const char *program_name, int *exit_status);
int		nmap_prepare_scan_config(t_nmap_config *config, int *exit_status);
int		nmap_prepare_target_file(t_nmap_config *config, int *exit_status);

/* resolve */
int		nmap_prepare_target(t_nmap_config *config, int *exit_status);
int		nmap_prepare_route(t_nmap_config *config, int *exit_status);

/* net */
int		nmap_prepare_send_socket(t_nmap_config *config, int *exit_status);
int		nmap_prepare_pcap(t_nmap_config *config, int *exit_status);

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

/*run*/
int		nmap_run_single_target(t_nmap_config *config, const char *target, int *exit_status);
int		nmap_run_target_file(t_nmap_config *config, int *exit_status);

/* output */
void	nmap_print_report(t_nmap_config *config);

/* parsing */
int     nmap_parse_ports(t_nmap_config *config, const char *arg);
int	    parse_flag(t_nmap_config *config, int argc, char **argv, int *i);
int	    parse_ip(t_nmap_config *config, int argc, char **argv, int *i);
int	    parse_port(t_nmap_config *config, int argc, char **argv, int *i);
int	    parse_scan(t_nmap_config *config, int argc, char **argv, int *i);
int	    parse_speedup(t_nmap_config *config, int argc, char **argv, int *i);
int		parse_timeout(t_nmap_config *config, int argc, char **argv, int *i);
int		parse_file(t_nmap_config *config, int argc, char **argv, int *i);
int		nmap_parse_cli(t_nmap_config *config, int argc, char **argv, int *exit_status);
int	    scan_name_to_mask(const char *name, uint32_t *mask);

/* parsing utils */
int	    nmap_streq(const char *a, const char *b);
int	    nmap_is_number(const char *s);
int	    nmap_parse_int(const char *s, int *out);

/* signal */
int		nmap_signal_setup(int *exit_status);
int		nmap_signal_stop_requested(void);
#endif