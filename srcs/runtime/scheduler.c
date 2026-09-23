#include "ft_nmap.h"
#include "debug/debug.h"
#include "packet/packet.h"
#include "runtime/runtime_internal.h"
#include "runtime/worker.h"

/** Both policies share queue accounting, never each other's pacing rules. */
static int can_reserve_locked(const t_nmap_target_ctx *ctx,
        const t_probe *probe, uint64_t now)
{
    const t_nmap_runtime *rt = &ctx->runtime;

    if (probe->state != PROBE_PENDING)
        return (0);
    if (ctx->scan->thread_count != 0)
        return (1); /* Naive: absolutely no per-target pacing/window. */
    if (rt->queued_count + rt->outstanding_count
        >= (size_t)ctx->scan->window_size)
        return (0);
    if (!nmap_probe_is_udp(probe))
        return (1);
    if (rt->udp_queued_count + rt->udp_outstanding_count
        >= rt->timing.udp_window || rt->udp_queued_count > 0)
        return (0);
    if (rt->timing.udp_send_gap_ms == 0 || rt->last_udp_sent_ms == 0)
        return (1);
    return (now > rt->last_udp_sent_ms
        && now - rt->last_udp_sent_ms >= rt->timing.udp_send_gap_ms);
}

/** Select one probe, preserving a round-robin cursor WITHIN each target. */
static t_probe *reserve_one(t_nmap_target_ctx *ctx,
        uint64_t now, uint32_t *dispatch_id)
{
    t_nmap_runtime *rt = &ctx->runtime;
    t_probe *probe;
    size_t i;
    size_t idx;

    pthread_mutex_lock(&rt->lock);
    if (rt->probe_count == rt->done_count + rt->queued_count
        + rt->outstanding_count + rt->benched_count)
    {
        pthread_mutex_unlock(&rt->lock);
        return (NULL);
    }
    for (i = 0; i < rt->probe_count; ++i)
    {
        idx = (ctx->next_probe_cursor + i) % rt->probe_count;
        probe = &rt->probes[idx];
        if (!can_reserve_locked(ctx, probe, now))
            continue ;
        probe->state = PROBE_QUEUED;
        probe->dispatch_id++;
        if (probe->dispatch_id == 0)
            probe->dispatch_id = 1; /* 0 means no active send token. */
        probe->sending_dispatch_id = 0;
        rt->queued_count++;
        atomic_fetch_add_explicit(&ctx->iface->inflight_jobs, 1,
            memory_order_release);
        atomic_fetch_add_explicit(&ctx->engine->inflight_jobs, 1,
            memory_order_release);
        if (nmap_probe_is_udp(probe))
            rt->udp_queued_count++;
        ctx->next_probe_cursor = (idx + 1) % rt->probe_count;
        *dispatch_id = probe->dispatch_id;
        pthread_mutex_unlock(&rt->lock);
        return (probe);
    }
    pthread_mutex_unlock(&rt->lock);
    return (NULL);
}

static void undo_reservation(t_nmap_target_ctx *ctx,
        t_probe *probe, uint32_t generation)
{
    t_nmap_runtime *rt = &ctx->runtime;

    pthread_mutex_lock(&rt->lock);
    if (probe->state == PROBE_QUEUED
        && probe->dispatch_id == generation
        && probe->sending_dispatch_id == 0)
    {
        probe->state = PROBE_PENDING;
        --rt->queued_count;
        nmap_release_inflight(ctx);
        if (nmap_probe_is_udp(probe))
            --rt->udp_queued_count;
    }
    pthread_mutex_unlock(&rt->lock);
}

static int dispatch_one(t_nmap_engine *engine, t_nmap_target_ctx *ctx,
        t_probe *probe, uint32_t id, int *exit_status)
{
    t_probe snapshot;

    if (engine->sender_pool.worker_count > 0)
    {
        if (nmap_dispatch_probe_to_sender(engine, ctx, probe, id))
            return (1);
        undo_reservation(ctx, probe, id);
        if (!nmap_sender_pool_has_error(engine))
            return (1);
    }
    else if (nmap_runtime_begin_send(ctx, probe, id, &snapshot))
    {
        DEBUG_PROBE_SEND(&snapshot);
        if (nmap_send_probe(ctx, probe))
        {
            nmap_runtime_complete_send(ctx, probe, id, nmap_now_ms());
            return (1);
        }
        (void)nmap_runtime_fail_send(ctx, probe, id);
    }
    else
        return (1);
    if (exit_status)
        *exit_status = 1;
    return (0);
}

/**
 * Naive: only N global reserved+outstanding slots. Adaptive: a separate shared
 * cap for each interface plus target-local timing/UDP congestion behavior.
 * Both policies distribute successive reservations across different targets.
 */
int nmap_runtime_schedule_ready(t_nmap_engine *engine, int *exit_status)
{
    t_nmap_target_ctx *ctx;
    t_probe *probe;
    uint32_t id;
    size_t checked;
    size_t pos;
    size_t limit;
    int naive;

    if (!engine)
        goto fail;
    naive = (engine->sender_pool.worker_count > 0);
    limit = (size_t)engine->sender_pool.worker_count;
    while (engine->active_count > 0)
    {
        if (nmap_sender_pool_has_error(engine))
            goto fail;
        if (naive && atomic_load_explicit(&engine->inflight_jobs, memory_order_acquire) >= limit)
            return (1);
        for (checked = 0; checked < engine->target_count; ++checked)
        {
            pos = (engine->target_cursor + checked) % engine->target_count;
            ctx = &engine->targets[pos];
            if (ctx->status != NMAP_TARGET_ACTIVE)
                continue ;
            if (!naive && atomic_load_explicit(&ctx->iface->inflight_jobs, memory_order_acquire)
                >= ctx->iface->adaptive_window)
                continue ;
            probe = reserve_one(ctx, nmap_now_ms(), &id);
            if (!probe)
                continue ;
            engine->target_cursor = (pos + 1) % engine->target_count;
            if (!dispatch_one(engine, ctx, probe, id, exit_status))
                return (0);
            break ;
        }
        if (checked == engine->target_count)
            return (1); /* No eligible work until reply/deadline/pacing. */
    }
    return (1);
fail:
    if (exit_status)
        *exit_status = 1;
    return (0);
}
