#ifndef NMAP_ENGINE_INTERNAL_H
# define NMAP_ENGINE_INTERNAL_H

# include "config.h"

int  nmap_engine_prepare(t_nmap_engine *engine, const t_nmap_config *config);
void nmap_engine_activate(t_nmap_engine *engine);
int  nmap_engine_run_loop(t_nmap_engine *engine, int *exit_status);

#endif
