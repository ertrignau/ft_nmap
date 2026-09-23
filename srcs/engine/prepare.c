#include "ft_nmap.h"
#include "engine/engine_internal.h"
#include "debug/debug.h"
#include "net/address.h"
#include "runtime/runtime_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static size_t count_scan_types(uint32_t mask)
{
    size_t n = 0;
    while (mask)
    {
        n += (mask & 1U);
        mask >>= 1;
    }
    return (n);
}

static t_nmap_iface_ctx *find_or_add_iface(t_nmap_engine *engine,
        const t_nmap_route *route)
{
    t_nmap_iface_ctx *iface;
    size_t i;

    for (i = 0; i < engine->iface_count; ++i)
        if (engine->ifaces[i].ifindex == route->ifindex)
            return (&engine->ifaces[i]);
    iface = &engine->ifaces[engine->iface_count++];
    memset(iface, 0, sizeof(*iface));
    memcpy(iface->iface, route->iface, sizeof(iface->iface));
    iface->ifindex = route->ifindex;
    atomic_init(&iface->inflight_jobs, 0);
    iface->capture.fd = -1;
    iface->capture.datalink = -1;
    iface->socket4.send_fd = -1;
    iface->socket6.send_fd = -1;
    iface->adaptive_window = (size_t)engine->config->scan.window_size;
    if (iface->adaptive_window == 0)
        iface->adaptive_window = 1;
    return (iface);
}

static int is_duplicate(const t_nmap_engine *engine, size_t at)
{
    const t_nmap_target_ctx *ctx = &engine->targets[at];
    size_t i;

    for (i = 0; i < at; ++i)
    {
        const t_nmap_target_ctx *prev = &engine->targets[i];
        if (prev->status == NMAP_TARGET_DUPLICATE
            || prev->status == NMAP_TARGET_FAILED)
            continue ;
        if (prev->route.ifindex == ctx->route.ifindex
            && nmap_ip_equal(&prev->route.src_addr, &ctx->route.src_addr)
            && nmap_ip_equal(&prev->target.addr, &ctx->target.addr))
            return (1);
    }
    return (0);
}

/** Pre-resolve all targets, group by kernel-selected interface, open shared IO. */
int nmap_engine_prepare(t_nmap_engine *engine, const t_nmap_config *config)
{
    t_nmap_target_ctx *ctx;
    size_t i;
    int status;

    memset(engine, 0, sizeof(*engine));
    engine->config = config;
    atomic_init(&engine->inflight_jobs, 0);
    engine->target_count = config->targets.count;
    engine->targets = calloc(engine->target_count, sizeof(*engine->targets));
    engine->ifaces = calloc(engine->target_count, sizeof(*engine->ifaces));
    if (!engine->targets || !engine->ifaces)
        return (0);
    engine->max_active = (config->scan.thread_count > 0)
        ? (size_t)config->scan.thread_count : 32U;
    if (engine->max_active > engine->target_count)
        engine->max_active = engine->target_count;
    for (i = 0; i < engine->target_count; ++i)
    {
        ctx = &engine->targets[i];
        ctx->engine = engine;
        ctx->scan = &config->scan;
        atomic_init(&ctx->live_jobs, 0);
        status = 0;
        if (!nmap_prepare_target(ctx, config->targets.items[i], &status)
            || !nmap_prepare_route(ctx, &status))
        {
            ctx->status = NMAP_TARGET_FAILED;
            engine->failed_count++;
            continue ;
        }
        if (is_duplicate(engine, i))
        {
            ctx->status = NMAP_TARGET_DUPLICATE;
            fprintf(stderr, "ft_nmap: duplicate resolved destination %s (%s), skipped\n",
                ctx->target.ip, config->targets.items[i]);
            continue ;
        }
        ctx->iface = find_or_add_iface(engine, &ctx->route);
        if (!nmap_prepare_send_socket(ctx->iface, ctx->target.addr.family,
                &status))
        {
            ctx->status = NMAP_TARGET_FAILED;
            engine->failed_count++;
            continue ;
        }
        ctx->socket = (ctx->target.addr.family == AF_INET)
            ? &ctx->iface->socket4 : &ctx->iface->socket6;
        ctx->status = NMAP_TARGET_PREPARED;
        engine->planned_probes += config->scan.port_count
            * count_scan_types(config->scan.scan_mask);
    }
    for (i = 0; i < engine->iface_count; ++i)
    {
        t_nmap_iface_ctx *iface = &engine->ifaces[i];
        int used = 0;
        size_t j;
        for (j = 0; j < engine->target_count; ++j)
            if (engine->targets[j].status == NMAP_TARGET_PREPARED
                && engine->targets[j].iface == iface)
                used = 1;
        if (!used)
            continue ;
        status = 0;
        if (nmap_prepare_pcap(iface, &status))
            continue ;
        for (j = 0; j < engine->target_count; ++j)
        {
            ctx = &engine->targets[j];
            if (ctx->status != NMAP_TARGET_PREPARED || ctx->iface != iface)
                continue ;
            ctx->status = NMAP_TARGET_FAILED;
            engine->failed_count++;
            engine->planned_probes -= config->scan.port_count
                * count_scan_types(config->scan.scan_mask);
        }
    }
    for (i = 0; i < engine->target_count; ++i)
        if (engine->targets[i].status != NMAP_TARGET_DUPLICATE)
            engine->effective_targets++;
    return (1);
}

/** Activate targets round-robin across interfaces, not merely input order. */
void nmap_engine_activate(t_nmap_engine *engine)
{
    size_t checked;
    size_t i;
    size_t position;
    t_nmap_target_ctx *ctx;
    int error;
    int found;

    while (engine->active_count < engine->max_active)
    {
        found = 0;
        for (checked = 0; checked < engine->iface_count; ++checked)
        {
            position = (engine->iface_cursor + checked) % engine->iface_count;
            for (i = 0; i < engine->target_count; ++i)
            {
                ctx = &engine->targets[i];
                if (ctx->status == NMAP_TARGET_PREPARED
                    && ctx->iface == &engine->ifaces[position])
                {
                    found = 1;
                    break ;
                }
            }
            if (found)
                break ;
        }
        if (!found)
            return ;
        engine->iface_cursor = (position + 1) % engine->iface_count;
        error = 0;
        if (!nmap_prepare_runtime(ctx, &error))
        {
            fprintf(stderr, "ft_nmap: cannot allocate runtime for %s\n",
                ctx->target.ip);
            ctx->status = NMAP_TARGET_FAILED;
            engine->failed_count++;
            engine->planned_probes -= engine->config->scan.port_count
                * count_scan_types(engine->config->scan.scan_mask);
            continue ;
        }
        ctx->status = NMAP_TARGET_ACTIVE;
        ctx->started_ms = nmap_now_ms();
        ctx->iface->active_targets++;
        engine->active_count++;
        DEBUG_DEV_CONFIG(ctx);
        DEBUG_SOCKET(ctx);
        DEBUG_PCAP(ctx);
        DEBUG_RUNTIME(ctx);
    }
}
