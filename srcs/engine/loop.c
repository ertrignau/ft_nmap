#include "ft_nmap.h"
#include "engine/engine_internal.h"
#include "output/output.h"
#include "runtime/runtime_internal.h"

#include <stdio.h>
#include <stdlib.h>

/** Keep completed probe results for ordered reporting, after all senders retire. */
static void collect_finished(t_nmap_engine *engine)
{
    size_t i;
    t_nmap_target_ctx *ctx;

    for (i = 0; i < engine->target_count; ++i)
    {
        ctx = &engine->targets[i];
        if (ctx->status != NMAP_TARGET_ACTIVE
            || !nmap_runtime_is_finished(ctx)
            || atomic_load_explicit(&ctx->live_jobs, memory_order_acquire))
            continue ;
        ctx->finished_ms = nmap_now_ms();
        engine->finished_probes += ctx->runtime.probe_count;
        ctx->status = NMAP_TARGET_FINISHED;
        engine->completed_count++;
        engine->active_count--;
        ctx->iface->active_targets--;
        nmap_archive_target_ctx(ctx);
    }
}

/** Freeze per-target counters while holding their own locks, then print outside. */
static void report_progress(t_nmap_engine *engine)
{
    t_nmap_progress global = {0};
    t_nmap_target_progress *sources;
    t_nmap_target_ctx *ctx;
    size_t per_target_probes;
    size_t accounted;
    size_t i;

    sources = calloc(engine->target_count, sizeof(*sources));
    if (!sources)
    {
        fprintf(stderr, "ft_nmap: cannot allocate progress snapshot\n");
        return ;
    }
    {
        uint32_t mask;

        mask = engine->config->scan.scan_mask;
        per_target_probes = 0;
        while (mask)
        {
            per_target_probes += (size_t)(mask & 1U);
            mask >>= 1;
        }
        per_target_probes *= engine->config->scan.port_count;
    }
    global.total = engine->planned_probes;
    for (i = 0; i < engine->target_count; ++i)
    {
        ctx = &engine->targets[i];
        sources[i].name = ctx->target.ip[0] ? ctx->target.ip
            : engine->config->targets.items[i];
        sources[i].status = ctx->status;
        sources[i].ifindex = ctx->iface ? ctx->iface->ifindex : 0;
        if (ctx->status == NMAP_TARGET_PREPARED)
            sources[i].total = per_target_probes;
        if (ctx->status == NMAP_TARGET_FINISHED)
        {
            sources[i].total = ctx->runtime.probe_count;
            sources[i].done = ctx->runtime.probe_count;
        }
        if (ctx->status != NMAP_TARGET_ACTIVE)
        {
            global.done += sources[i].done;
            continue ;
        }
        pthread_mutex_lock(&ctx->runtime.lock);
        sources[i].total = ctx->runtime.probe_count;
        sources[i].done = ctx->runtime.done_count;
        sources[i].queued = ctx->runtime.queued_count;
        sources[i].outstanding = ctx->runtime.outstanding_count;
        sources[i].benched = ctx->runtime.benched_count;
        pthread_mutex_unlock(&ctx->runtime.lock);
        global.done += sources[i].done;
        global.queued += sources[i].queued;
        global.outstanding += sources[i].outstanding;
        global.benched += sources[i].benched;
    }
    accounted = global.done + global.queued + global.outstanding
        + global.benched;
    global.pending = (accounted < global.total) ? global.total - accounted : 0;
    global.elapsed_ms = nmap_now_ms() - engine->started_ms;
    nmap_output_print_target_progress(&global, sources, engine->target_count,
        engine->ifaces, engine->iface_count,
        engine->completed_count, engine->effective_targets);
    free(sources);
}

static int has_prepared(const t_nmap_engine *engine)
{
    size_t i;

    for (i = 0; i < engine->target_count; ++i)
        if (engine->targets[i].status == NMAP_TARGET_PREPARED)
            return (1);
    return (0);
}

/** One poll-driven loop controls every interface and every active target. */
int nmap_engine_run_loop(t_nmap_engine *engine, int *exit_status)
{
    size_t i;
    int wait_result;

    nmap_engine_activate(engine);
    while ((engine->active_count > 0 || has_prepared(engine))
        && !nmap_signal_stop_requested())
    {
        /* Replies before deadlines; bounded drain ensures interface fairness. */
        for (i = 0; i < engine->iface_count; ++i)
            if (engine->ifaces[i].active_targets > 0
                && !nmap_runtime_drain_replies(engine, &engine->ifaces[i],
                    exit_status))
                return (0);
        for (i = 0; i < engine->target_count; ++i)
            if (engine->targets[i].status == NMAP_TARGET_ACTIVE)
                nmap_runtime_expire_probes(&engine->targets[i]);
        collect_finished(engine);
        nmap_engine_activate(engine);
        if (engine->active_count == 0)
            continue ;
        if (!nmap_runtime_schedule_ready(engine, exit_status))
            return (0);
        if (nmap_sender_pool_has_error(engine))
            goto fail;
        wait_result = nmap_runtime_wait(engine, exit_status);
        if (wait_result == NMAP_WAIT_ERROR)
            return (0);
        if (wait_result == NMAP_WAIT_PROGRESS)
            report_progress(engine);
    }
    if (nmap_signal_stop_requested())
    {
        if (exit_status)
            *exit_status = 130;
        return (0);
    }
    if (nmap_sender_pool_has_error(engine))
        goto fail;
    return (1);
fail:
    if (exit_status)
        *exit_status = 1;
    return (0);
}
