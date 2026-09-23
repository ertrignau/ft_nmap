#include "runtime/worker.h"
#include "debug/debug.h"
#include "packet/packet.h"
#include "runtime/runtime_internal.h"

#include <stdlib.h>
#include <string.h>

/** Each worker owns at most one reserved or OUTSTANDING probe at a time. */
static int pool_pop_job(t_nmap_sender_pool *pool, t_nmap_send_job *job)
{
    pthread_mutex_lock(&pool->lock);
    while (pool->queue_count == 0 && !pool->stop_requested)
        pthread_cond_wait(&pool->cond, &pool->lock);
    if (pool->stop_requested)
    {
        pthread_mutex_unlock(&pool->lock);
        return (0);
    }
    *job = pool->queue[pool->queue_head];
    pool->queue_head = (pool->queue_head + 1) % pool->queue_capacity;
    pool->queue_count--;
    pthread_mutex_unlock(&pool->lock);
    return (1);
}

static int pool_is_stopping(t_nmap_sender_pool *pool)
{
    int stopping;

    pthread_mutex_lock(&pool->lock);
    stopping = pool->stop_requested;
    pthread_mutex_unlock(&pool->lock);
    return (stopping);
}

static void set_send_error(t_nmap_sender_pool *pool)
{
    pthread_mutex_lock(&pool->lock);
    pool->send_error = 1;
    pthread_mutex_unlock(&pool->lock);
}

/** Never hold pool.lock while blocking on a target's probe_cond. */
static void wait_for_probe(t_nmap_worker *worker,
        t_nmap_target_ctx *ctx, t_probe *probe)
{
    t_nmap_runtime *rt = &ctx->runtime;
    t_nmap_sender_pool *pool = &worker->engine->sender_pool;

    pthread_mutex_lock(&rt->lock);
    while (probe->state == PROBE_OUTSTANDING)
    {
        if (pool_is_stopping(pool))
            break ;
        pthread_cond_wait(&rt->probe_cond, &rt->lock);
    }
    pthread_mutex_unlock(&rt->lock);
}

static int execute_job(t_nmap_worker *worker, const t_nmap_send_job *job)
{
    t_probe snapshot;
    int fatal;

    if (!nmap_runtime_begin_send(job->ctx, job->probe,
            job->dispatch_id, &snapshot))
        return (0);
    DEBUG_PROBE_SEND(&snapshot);
    if (!nmap_send_probe(job->ctx, job->probe))
    {
        fatal = nmap_runtime_fail_send(job->ctx, job->probe,
                job->dispatch_id);
        if (fatal)
            set_send_error(&worker->engine->sender_pool);
        return (0);
    }
    nmap_runtime_complete_send(job->ctx, job->probe,
        job->dispatch_id, nmap_now_ms());
    return (1);
}

static void *worker_main(void *arg)
{
    t_nmap_worker *worker = arg;
    t_nmap_send_job job;

    while (pool_pop_job(&worker->engine->sender_pool, &job))
    {
        if (execute_job(worker, &job))
            wait_for_probe(worker, job.ctx, job.probe);
        /* Main cannot reclaim target runtime until all such tickets retire. */
        atomic_fetch_sub_explicit(&job.ctx->live_jobs, 1,
            memory_order_release);
    }
    return (NULL);
}

int nmap_prepare_sender_pool(t_nmap_engine *engine, int *exit_status)
{
    t_nmap_sender_pool *pool;
    int i;

    if (!engine)
        goto fail;
    pool = &engine->sender_pool;
    memset(pool, 0, sizeof(*pool));
    pool->worker_count = engine->config->scan.thread_count;
    if (pool->worker_count <= 0)
        return (1);
    if (pthread_mutex_init(&pool->lock, NULL) != 0)
        goto fail;
    if (pthread_cond_init(&pool->cond, NULL) != 0)
    {
        pthread_mutex_destroy(&pool->lock);
        goto fail;
    }
    pool->initialized = 1;
    /* The scheduler's global N-slot invariant bounds queue occupancy by N. */
    pool->queue_capacity = (size_t)pool->worker_count;
    pool->queue = calloc(pool->queue_capacity, sizeof(*pool->queue));
    pool->workers = calloc(pool->worker_count, sizeof(*pool->workers));
    if (!pool->queue || !pool->workers)
        goto fail_initialized;
    for (i = 0; i < pool->worker_count; ++i)
    {
        pool->workers[i].engine = engine;
        pool->workers[i].id = i;
        if (pthread_create(&pool->workers[i].thread, NULL,
                worker_main, &pool->workers[i]) != 0)
            goto fail_initialized;
        pool->workers[i].started = 1;
    }
    return (1);
fail_initialized:
    nmap_stop_sender_pool(engine);
fail:
    if (exit_status)
        *exit_status = 1;
    return (0);
}

void nmap_stop_sender_pool(t_nmap_engine *engine)
{
    t_nmap_sender_pool *pool;
    size_t i;

    if (!engine || !engine->sender_pool.initialized)
        return ;
    pool = &engine->sender_pool;
    pthread_mutex_lock(&pool->lock);
    pool->stop_requested = 1;
    pthread_cond_broadcast(&pool->cond);
    pthread_mutex_unlock(&pool->lock);
    for (i = 0; i < engine->target_count; ++i)
    {
        t_nmap_runtime *rt = &engine->targets[i].runtime;
        if (!rt->lock_initialized || !rt->probe_cond_initialized)
            continue ;
        pthread_mutex_lock(&rt->lock);
        pthread_cond_broadcast(&rt->probe_cond);
        pthread_mutex_unlock(&rt->lock);
    }
    for (i = 0; i < (size_t)pool->worker_count; ++i)
        if (pool->workers && pool->workers[i].started)
            pthread_join(pool->workers[i].thread, NULL);
    free(pool->workers);
    free(pool->queue);
    pthread_cond_destroy(&pool->cond);
    pthread_mutex_destroy(&pool->lock);
    memset(pool, 0, sizeof(*pool));
}

int nmap_sender_pool_has_error(t_nmap_engine *engine)
{
    int err;
    t_nmap_sender_pool *pool;

    if (!engine || !engine->sender_pool.initialized)
        return (0);
    pool = &engine->sender_pool;
    pthread_mutex_lock(&pool->lock);
    err = pool->send_error;
    pthread_mutex_unlock(&pool->lock);
    return (err);
}

int nmap_dispatch_probe_to_sender(t_nmap_engine *engine,
        t_nmap_target_ctx *ctx, t_probe *probe, uint32_t dispatch_id)
{
    t_nmap_sender_pool *pool;

    if (!engine || !ctx || !probe || !engine->sender_pool.initialized)
        return (0);
    pool = &engine->sender_pool;
    pthread_mutex_lock(&pool->lock);
    if (pool->stop_requested || pool->send_error
        || pool->queue_count >= pool->queue_capacity)
    {
        pthread_mutex_unlock(&pool->lock);
        return (0);
    }
    /* Ticket is visible BEFORE another thread can pop this queue item. */
    atomic_fetch_add_explicit(&ctx->live_jobs, 1, memory_order_relaxed);
    pool->queue[pool->queue_tail] = (t_nmap_send_job){ctx, probe, dispatch_id};
    pool->queue_tail = (pool->queue_tail + 1) % pool->queue_capacity;
    pool->queue_count++;
    pthread_cond_signal(&pool->cond);
    pthread_mutex_unlock(&pool->lock);
    return (1);
}
