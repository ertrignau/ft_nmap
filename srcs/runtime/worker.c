#include "runtime/worker.h"
#include "debug/debug.h"
#include "packet/packet.h"
#include "runtime/runtime_internal.h"

#include <stdlib.h>
#include <string.h>

/**
 * @brief Pop one job from the shared sender queue, blocking until work/stop.
 */
static int	pool_pop_job(t_nmap_sender_pool *pool, t_nmap_send_job *job)
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

/** Return whether pool shutdown has been requested. */
static int	pool_is_stopping(t_nmap_sender_pool *pool)
{
	int	stopping;

	pthread_mutex_lock(&pool->lock);
	stopping = pool->stop_requested;
	pthread_mutex_unlock(&pool->lock);
	return (stopping);
}

/** Record a fatal sender error visible to the main event loop. */
static void	set_send_error(t_nmap_sender_pool *pool)
{
	pthread_mutex_lock(&pool->lock);
	pool->send_error = 1;
	pthread_mutex_unlock(&pool->lock);
}

/**
 * @brief Wait until the main thread releases this physical attempt.
 *
 * The worker owns no receive path. Once sendto() succeeds, it cannot consume
 * another job while this probe remains OUTSTANDING.
 *
 * The main thread releases it by changing the probe to:
 *
 *   DONE      valid reply or final timeout
 *   PENDING   timeout requiring another retry
 *   BENCHED   UDP retry temporarily held by adaptive policy
 *
 * A single shared condition variable is deliberately used for simplicity.
 * broadcast wakes all workers; each one re-checks its own probe predicate.
 */
static void	wait_for_probe(t_nmap_worker *worker, t_probe *probe)
{
	t_nmap_runtime		*runtime;
	t_nmap_sender_pool	*pool;

	runtime = &worker->config->runtime;
	pool = &worker->config->sender_pool;
	pthread_mutex_lock(&runtime->lock);
	while (probe->state == PROBE_OUTSTANDING)
	{
		if (pool_is_stopping(pool))
			break ;
		pthread_cond_wait(&runtime->probe_cond, &runtime->lock);
	}
	pthread_mutex_unlock(&runtime->lock);
}

/**
 * @brief Execute exactly one already-reserved physical send.
 *
 * @return 1 when sendto() succeeded and the worker must wait for the main
 *         thread to resolve/expire this attempt, 0 for stale/failed jobs.
 */
static int	execute_job(t_nmap_worker *worker,
		const t_nmap_send_job *job)
{
	t_probe		snapshot;
	uint64_t	sent_at_ms;
	int			fatal;

	if (!nmap_runtime_begin_send(worker->config, job->probe,
			job->dispatch_id, &snapshot))
		return (0);
	DEBUG_PROBE_SEND(&snapshot);
	if (!nmap_send_probe(worker->config, job->probe))
	{
		fatal = nmap_runtime_fail_send(worker->config,
				job->probe, job->dispatch_id);
		if (fatal)
			set_send_error(&worker->config->sender_pool);
		return (0);
	}
	sent_at_ms = nmap_now_ms();
	nmap_runtime_complete_send(worker->config, job->probe,
		job->dispatch_id, sent_at_ms);
	return (1);
}

/**
 * @brief Sender worker entry point.
 *
 * One worker has at most one physical probe in flight.
 *
 * It only:
 *   1. consumes one reserved job,
 *   2. sends it,
 *   3. waits until the main thread resolves/expires that attempt,
 *   4. consumes another job.
 *
 * Pcap, matching, classification, retry policy and timeout policy stay owned
 * exclusively by the main event loop.
 */
static void	*worker_main(void *arg)
{
	t_nmap_worker	*worker;
	t_nmap_send_job	job;

	worker = (t_nmap_worker *)arg;
	while (pool_pop_job(&worker->config->sender_pool, &job))
	{
		if (execute_job(worker, &job))
			wait_for_probe(worker, job.probe);
	}
	return (NULL);
}

/** Initialize and start one sender worker. */
static int	init_worker(t_nmap_config *config, t_nmap_worker *worker,
		int id)
{
	memset(worker, 0, sizeof(*worker));
	worker->config = config;
	worker->id = id;
	if (pthread_create(&worker->thread, NULL, worker_main, worker) != 0)
		return (0);
	worker->started = 1;
	return (1);
}

/**
 * @brief Initialize the shared sender queue and requested worker threads.
 *
 * @note speedup=0 intentionally keeps an inline main-thread sender and does
 *       not initialize pool synchronization primitives.
 */
int	nmap_prepare_sender_pool(t_nmap_config *config, int *exit_status)
{
	int	i;

	if (!config)
		goto fail;
	memset(&config->sender_pool, 0, sizeof(config->sender_pool));
	config->sender_pool.worker_count = config->scan.thread_count;
	if (config->sender_pool.worker_count <= 0)
	{
		config->sender_pool.worker_count = 0;
		return (1);
	}
	if (pthread_mutex_init(&config->sender_pool.lock, NULL) != 0)
		goto fail;
	if (pthread_cond_init(&config->sender_pool.cond, NULL) != 0)
	{
		pthread_mutex_destroy(&config->sender_pool.lock);
		goto fail;
	}
	config->sender_pool.initialized = 1;
	config->sender_pool.queue_capacity = config->runtime.probe_count;
	if (config->sender_pool.queue_capacity == 0)
		goto fail_initialized;
	config->sender_pool.queue = calloc(config->sender_pool.queue_capacity,
			sizeof(*config->sender_pool.queue));
	config->sender_pool.workers = calloc(config->sender_pool.worker_count,
			sizeof(*config->sender_pool.workers));
	if (!config->sender_pool.queue || !config->sender_pool.workers)
		goto fail_initialized;
	i = 0;
	while (i < config->sender_pool.worker_count)
	{
		if (!init_worker(config, &config->sender_pool.workers[i], i))
			goto fail_initialized;
		i++;
	}
	return (1);
fail_initialized:
	if (exit_status)
		*exit_status = 1;
	nmap_stop_sender_pool(config);
	return (0);
fail:
	if (exit_status)
		*exit_status = 1;
	return (0);
}

/**
 * @brief Stop and join every sender worker, then release pool resources.
 */
void	nmap_stop_sender_pool(t_nmap_config *config)
{
	int	i;

	if (!config || !config->sender_pool.initialized)
		return ;
	pthread_mutex_lock(&config->sender_pool.lock);
	config->sender_pool.stop_requested = 1;
	pthread_cond_broadcast(&config->sender_pool.cond);
	pthread_mutex_unlock(&config->sender_pool.lock);

	/*
	 * Some workers may be waiting for an OUTSTANDING probe rather than for a
	 * queue job. Wake them as well so they can observe stop_requested.
	 */
	if (config->runtime.probe_cond_initialized)
	{
		pthread_mutex_lock(&config->runtime.lock);
		pthread_cond_broadcast(&config->runtime.probe_cond);
		pthread_mutex_unlock(&config->runtime.lock);
	}

	i = 0;
	while (i < config->sender_pool.worker_count)
	{
		if (config->sender_pool.workers
			&& config->sender_pool.workers[i].started)
			pthread_join(config->sender_pool.workers[i].thread, NULL);
		i++;
	}
	free(config->sender_pool.workers);
	free(config->sender_pool.queue);
	pthread_cond_destroy(&config->sender_pool.cond);
	pthread_mutex_destroy(&config->sender_pool.lock);
	memset(&config->sender_pool, 0, sizeof(config->sender_pool));
}

/** Return whether any relevant sender job reported a fatal send failure. */
int	nmap_sender_pool_has_error(t_nmap_config *config)
{
	int	error;

	if (!config || !config->sender_pool.initialized)
		return (0);
	pthread_mutex_lock(&config->sender_pool.lock);
	error = config->sender_pool.send_error;
	pthread_mutex_unlock(&config->sender_pool.lock);
	return (error != 0);
}

/**
 * @brief Push one already-reserved probe generation into the shared queue.
 */
int	nmap_dispatch_probe_to_sender(t_nmap_config *config, t_probe *probe,
		uint32_t dispatch_id)
{
	t_nmap_sender_pool	*pool;

	if (!config || !probe || !config->sender_pool.initialized)
		return (0);
	pool = &config->sender_pool;
	pthread_mutex_lock(&pool->lock);
	if (pool->stop_requested || pool->send_error
		|| pool->queue_count >= pool->queue_capacity)
	{
		pthread_mutex_unlock(&pool->lock);
		return (0);
	}
	pool->queue[pool->queue_tail].probe = probe;
	pool->queue[pool->queue_tail].dispatch_id = dispatch_id;
	pool->queue_tail = (pool->queue_tail + 1) % pool->queue_capacity;
	pool->queue_count++;
	pthread_cond_signal(&pool->cond);
	pthread_mutex_unlock(&pool->lock);
	return (1);
}
