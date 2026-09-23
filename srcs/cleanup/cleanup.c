#include "ft_nmap.h"
#include <pcap/pcap.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/** Caller must ensure no worker still references this context. */
void nmap_cleanup_target_ctx(t_nmap_target_ctx *ctx)
{
    t_nmap_runtime *rt;

    if (!ctx)
        return ;
    rt = &ctx->runtime;
    free(rt->probe_by_src_port);
    free(rt->probes);
    if (rt->probe_cond_initialized)
        pthread_cond_destroy(&rt->probe_cond);
    if (rt->lock_initialized)
        pthread_mutex_destroy(&rt->lock);
    memset(rt, 0, sizeof(*rt));
}

/** A finished target keeps ONLY its probes for its final ordered report.
 * The 65536-pointer matching table and synchronization resources are released
 * as soon as the last sender ticket retires, before activating more targets.
 */
void nmap_archive_target_ctx(t_nmap_target_ctx *ctx)
{
    t_nmap_runtime *rt;

    if (!ctx)
        return ;
    rt = &ctx->runtime;
    free(rt->probe_by_src_port);
    rt->probe_by_src_port = NULL;
    if (rt->probe_cond_initialized)
        pthread_cond_destroy(&rt->probe_cond);
    if (rt->lock_initialized)
        pthread_mutex_destroy(&rt->lock);
    rt->probe_cond_initialized = 0;
    rt->lock_initialized = 0;
    /* rt->probes and rt->probe_count survive until the final report. */
}

/** Shared resources are closed once, AFTER all senders have joined. */
void nmap_cleanup_engine(t_nmap_engine *engine)
{
    size_t i;

    if (!engine)
        return ;
    nmap_stop_sender_pool(engine);
    for (i = 0; engine->targets && i < engine->target_count; ++i)
        nmap_cleanup_target_ctx(&engine->targets[i]);
    for (i = 0; engine->ifaces && i < engine->iface_count; ++i)
    {
        t_nmap_iface_ctx *iface = &engine->ifaces[i];
        if (iface->capture.handle)
            pcap_close(iface->capture.handle);
        if (iface->socket4.send_fd >= 0)
            close(iface->socket4.send_fd);
        if (iface->socket6.send_fd >= 0)
            close(iface->socket6.send_fd);
    }
    free(engine->targets);
    free(engine->ifaces);
    memset(engine, 0, sizeof(*engine));
}

void nmap_cleanup_config(t_nmap_config *config)
{
    size_t i;

    if (!config)
        return ;
    for (i = 0; i < config->targets.count; ++i)
        free(config->targets.items[i]);
    free(config->targets.items);
    memset(config, 0, sizeof(*config));
}
