#ifndef NMAP_WORKER_H
# define NMAP_WORKER_H

# include "config.h"

/**
 * @brief One sender thread in the shared producer/consumer pool.
 *
 * @note A worker has deliberately no pcap handle and no classifier state.
 *       It sends one reserved job, then waits until the main thread resolves
 *       or expires that probe before consuming another job.
 */
struct s_nmap_worker
{
	pthread_t		thread;
	t_nmap_config	*config;
	int				id;
	int				started;
};

int		nmap_prepare_sender_pool(t_nmap_config *config, int *exit_status);
void	nmap_stop_sender_pool(t_nmap_config *config);
int		nmap_sender_pool_has_error(t_nmap_config *config);

int		nmap_dispatch_probe_to_sender(t_nmap_config *config,
			t_probe *probe, uint32_t dispatch_id);

#endif
