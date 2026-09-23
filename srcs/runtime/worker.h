#ifndef NMAP_WORKER_H
# define NMAP_WORKER_H

# include "config.h"

struct s_nmap_worker
{
    pthread_t       thread;
    t_nmap_engine   *engine;
    int             id;
    int             started;
};

int     nmap_prepare_sender_pool(t_nmap_engine *engine, int *exit_status);
void    nmap_stop_sender_pool(t_nmap_engine *engine);
int     nmap_sender_pool_has_error(t_nmap_engine *engine);
int     nmap_dispatch_probe_to_sender(t_nmap_engine *engine,
            t_nmap_target_ctx *ctx, t_probe *probe, uint32_t dispatch_id);

#endif
