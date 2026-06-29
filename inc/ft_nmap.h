#ifndef FT_NMAP_H
# define FT_NMAP_H

# include "config.h"

/* config */
int		nmap_load_hardcoded_dev_config(t_nmap_config *config);
void	nmap_cleanup_config(t_nmap_config *config);

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

/* output */
void	nmap_print_report(t_nmap_config *config);


/* signal */
int		nmap_signal_setup(int *exit_status);
int		nmap_signal_stop_requested(void);
#endif