#ifndef NMAP_WORKER_H
# define NMAP_WORKER_H

# include "config.h"
# include <pthread.h>

/**
 * @brief One sender worker.
 *
 * @note The worker never reads pcap and never classifies replies. It only waits
 *       for one assigned job, marks its probe as in-flight, sends it, then
 *       becomes available again.
 */
struct s_nmap_worker
{
	pthread_t		thread;
	pthread_mutex_t	lock;
	pthread_cond_t	cond;

	t_nmap_config	*config;
	t_probe			*job;

	int				id;
	int				started;
	int				stop_requested;
	int				job_pending;

	size_t			outstanding_count;
};

int		nmap_prepare_sender_pool(t_nmap_config *config, int *exit_status);
void	nmap_stop_sender_pool(t_nmap_config *config);
int		nmap_sender_pool_has_error(t_nmap_config *config);

int		nmap_dispatch_probe_to_sender(t_nmap_config *config, t_probe *probe);
void	nmap_sender_note_probe_done_locked(t_nmap_config *config,
			t_probe *probe);

#endif
