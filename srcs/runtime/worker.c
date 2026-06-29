#include "runtime/worker.h"
#include "debug/debug.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#define NMAP_MAX_WORKERS 250

int	nmap_send_tcp_probe(t_nmap_config *config, t_probe *probe);
int	nmap_send_udp_probe(t_nmap_config *config, t_probe *probe);

/**
 * @brief Return current time in milliseconds.
 *
 * @return Current timestamp in milliseconds.
 */
static uint64_t	get_time_ms(void)
{
	struct timeval	tv;

	gettimeofday(&tv, NULL);
	return ((uint64_t)tv.tv_sec * 1000 + (uint64_t)tv.tv_usec / 1000);
}

/**
 * @brief Check whether a scan type is TCP-based.
 *
 * @param scan_type Scan type stored in the probe.
 *
 * @return 1 for TCP scans, 0 otherwise.
 */
static int	is_tcp_scan(uint32_t scan_type)
{
	return (scan_type == NMAP_SCAN_SYN
		|| scan_type == NMAP_SCAN_NULL
		|| scan_type == NMAP_SCAN_FIN
		|| scan_type == NMAP_SCAN_XMAS
		|| scan_type == NMAP_SCAN_ACK);
}

/**
 * @brief Check whether a probe is UDP.
 *
 * @param probe Probe to inspect.
 *
 * @return 1 for UDP, 0 otherwise.
 */
static int	probe_is_udp(t_probe *probe)
{
	return (probe && probe->scan_type == NMAP_SCAN_UDP);
}

/**
 * @brief Send one probe through the packet layer.
 *
 * @param config Global nmap configuration.
 * @param probe Probe to send.
 *
 * @return 1 on success, 0 on send failure.
 *
 * @note The worker does not check scheduler capacity here. The main scheduler
 *       already decided that this probe may be dispatched.
 */
static int	send_probe(t_nmap_config *config, t_probe *probe)
{
	if (is_tcp_scan(probe->scan_type))
		return (nmap_send_tcp_probe(config, probe));
	if (probe->scan_type == NMAP_SCAN_UDP)
		return (nmap_send_udp_probe(config, probe));
	fprintf(stderr, "ft_nmap: invalid scan type: 0x%x\n", probe->scan_type);
	return (0);
}

/**
 * @brief Move a queued probe to in-flight immediately before sendto().
 *
 * @param worker Worker sending the probe.
 * @param probe Probe to mark.
 *
 * @return 1 if the probe may be sent, 0 if it was cancelled.
 *
 * @note QUEUED and IN_FLIGHT are counted separately. The timeout clock starts
 *       only here, just before the packet layer calls sendto().
 */
static int	mark_probe_sending(t_nmap_worker *worker, t_probe *probe)
{
	t_nmap_config	*config;

	config = worker->config;
	pthread_mutex_lock(&config->sender_pool.runtime_lock);
	if (config->sender_pool.stop_requested || probe->state != PROBE_QUEUED)
	{
		pthread_mutex_unlock(&config->sender_pool.runtime_lock);
		return (0);
	}
	if (config->runtime.queued_count > 0)
		config->runtime.queued_count--;
	config->runtime.in_flight_count++;
	if (probe_is_udp(probe))
	{
		if (config->runtime.udp_queued_count > 0)
			config->runtime.udp_queued_count--;
		config->runtime.udp_in_flight_count++;
	}
	worker->outstanding_count++;
	probe->sent_at_ms = get_time_ms();
	probe->state = PROBE_IN_FLIGHT;
	pthread_mutex_unlock(&config->sender_pool.runtime_lock);
	return (1);
}

/**
 * @brief Mark a worker slot available after the send attempt finished.
 *
 * @param worker Worker to update.
 */
static void	mark_worker_available(t_nmap_worker *worker)
{
	t_nmap_config	*config;

	config = worker->config;
	pthread_mutex_lock(&config->sender_pool.runtime_lock);
	worker->job_pending = 0;
	pthread_mutex_unlock(&config->sender_pool.runtime_lock);
}

/**
 * @brief Mark a send failure as a final probe failure.
 *
 * @param worker Worker that failed.
 * @param probe Probe that could not be sent.
 */
static void	mark_send_failed(t_nmap_worker *worker, t_probe *probe)
{
	t_nmap_config	*config;

	config = worker->config;
	pthread_mutex_lock(&config->sender_pool.runtime_lock);
	if (probe->state == PROBE_IN_FLIGHT)
	{
		probe->state = PROBE_DONE;
		probe->result = SCAN_RESULT_UNKNOWN;
		if (config->runtime.in_flight_count > 0)
			config->runtime.in_flight_count--;
		if (probe_is_udp(probe) && config->runtime.udp_in_flight_count > 0)
			config->runtime.udp_in_flight_count--;
		if (worker->outstanding_count > 0)
			worker->outstanding_count--;
		config->runtime.done_count++;
	}
	worker->job_pending = 0;
	config->sender_pool.send_error = 1;
	pthread_mutex_unlock(&config->sender_pool.runtime_lock);
}

/**
 * @brief Fetch the next assigned probe for a worker.
 *
 * @param worker Worker waiting for work.
 *
 * @return Assigned probe, or NULL when the worker must stop.
 */
static t_probe	*worker_wait_for_job(t_nmap_worker *worker)
{
	t_probe	*job;

	pthread_mutex_lock(&worker->lock);
	while (!worker->stop_requested && !worker->job)
		pthread_cond_wait(&worker->cond, &worker->lock);
	if (worker->stop_requested && !worker->job)
	{
		pthread_mutex_unlock(&worker->lock);
		return (NULL);
	}
	job = worker->job;
	worker->job = NULL;
	pthread_mutex_unlock(&worker->lock);
	return (job);
}

/**
 * @brief Sender worker entry point.
 *
 * @param arg Worker pointer.
 *
 * @return NULL.
 */
static void	*worker_main(void *arg)
{
	t_nmap_worker	*worker;
	t_probe			*job;

	worker = (t_nmap_worker *)arg;
	while (1)
	{
		job = worker_wait_for_job(worker);
		if (!job)
			break ;
		if (!mark_probe_sending(worker, job))
		{
			mark_worker_available(worker);
			continue ;
		}
		DEBUG_PROBE_SEND(job);
		if (!send_probe(worker->config, job))
			mark_send_failed(worker, job);
		else
			mark_worker_available(worker);
	}
	return (NULL);
}

/**
 * @brief Initialize one worker object.
 *
 * @param config Global nmap configuration.
 * @param worker Worker to initialize.
 * @param id Worker index.
 *
 * @return 1 on success, 0 on pthread initialization failure.
 */
static int	init_worker(t_nmap_config *config, t_nmap_worker *worker,
		int id)
{
	memset(worker, 0, sizeof(*worker));
	worker->config = config;
	worker->id = id;
	if (pthread_mutex_init(&worker->lock, NULL) != 0)
		return (0);
	if (pthread_cond_init(&worker->cond, NULL) != 0)
	{
		pthread_mutex_destroy(&worker->lock);
		return (0);
	}
	if (pthread_create(&worker->thread, NULL, worker_main, worker) != 0)
	{
		pthread_cond_destroy(&worker->cond);
		pthread_mutex_destroy(&worker->lock);
		return (0);
	}
	worker->started = 1;
	return (1);
}

/**
 * @brief Clamp requested speedup to the subject limit.
 *
 * @param requested Requested worker count.
 *
 * @return Worker count between 0 and NMAP_MAX_WORKERS.
 */
static int	normalize_worker_count(int requested)
{
	if (requested <= 0)
		return (0);
	if (requested > NMAP_MAX_WORKERS)
		return (NMAP_MAX_WORKERS);
	return (requested);
}

/**
 * @brief Prepare sender workers.
 *
 * @param config Global nmap configuration.
 * @param exit_status Output exit status set on fatal error.
 *
 * @return 1 on success, 0 on failure.
 *
 * @note The runtime lock is initialized even when speedup is 0 so cleanup and
 *       runtime helpers can stay simple.
 */
int	nmap_prepare_sender_pool(t_nmap_config *config, int *exit_status)
{
	int	i;

	if (!config)
	{
		if (exit_status)
			*exit_status = 1;
		return (0);
	}
	memset(&config->sender_pool, 0, sizeof(config->sender_pool));
	if (pthread_mutex_init(&config->sender_pool.runtime_lock, NULL) != 0)
	{
		if (exit_status)
			*exit_status = 1;
		return (0);
	}
	config->sender_pool.initialized = 1;
	config->sender_pool.worker_count = normalize_worker_count(config->cli.speedup);
	if (config->sender_pool.worker_count == 0)
		return (1);
	config->sender_pool.workers = calloc(config->sender_pool.worker_count,
			sizeof(t_nmap_worker));
	if (!config->sender_pool.workers)
	{
		if (exit_status)
			*exit_status = 1;
		return (0);
	}
	i = 0;
	while (i < config->sender_pool.worker_count)
	{
		if (!init_worker(config, &config->sender_pool.workers[i], i))
		{
			if (exit_status)
				*exit_status = 1;
			nmap_stop_sender_pool(config);
			return (0);
		}
		i++;
	}
	return (1);
}

/**
 * @brief Stop and join all sender workers.
 *
 * @param config Global nmap configuration.
 */
void	nmap_stop_sender_pool(t_nmap_config *config)
{
	int				i;
	t_nmap_worker	*worker;

	if (!config)
		return ;
	if (config->sender_pool.initialized)
	{
		pthread_mutex_lock(&config->sender_pool.runtime_lock);
		config->sender_pool.stop_requested = 1;
		pthread_mutex_unlock(&config->sender_pool.runtime_lock);
	}
	if (config->sender_pool.workers)
	{
		i = 0;
		while (i < config->sender_pool.worker_count)
		{
			worker = &config->sender_pool.workers[i];
			pthread_mutex_lock(&worker->lock);
			worker->stop_requested = 1;
			pthread_cond_signal(&worker->cond);
			pthread_mutex_unlock(&worker->lock);
			i++;
		}
		i = 0;
		while (i < config->sender_pool.worker_count)
		{
			worker = &config->sender_pool.workers[i];
			if (worker->started)
				pthread_join(worker->thread, NULL);
			pthread_cond_destroy(&worker->cond);
			pthread_mutex_destroy(&worker->lock);
			i++;
		}
		free(config->sender_pool.workers);
		config->sender_pool.workers = NULL;
	}
	if (config->sender_pool.initialized)
	{
		pthread_mutex_destroy(&config->sender_pool.runtime_lock);
		config->sender_pool.initialized = 0;
	}
	config->sender_pool.worker_count = 0;
}

/**
 * @brief Return whether a worker send error happened.
 *
 * @param config Global nmap configuration.
 *
 * @return 1 if a worker reported a fatal send error, 0 otherwise.
 */
int	nmap_sender_pool_has_error(t_nmap_config *config)
{
	int	error;

	if (!config || !config->sender_pool.initialized)
		return (0);
	pthread_mutex_lock(&config->sender_pool.runtime_lock);
	error = config->sender_pool.send_error;
	pthread_mutex_unlock(&config->sender_pool.runtime_lock);
	return (error != 0);
}

/**
 * @brief Check whether a worker can accept a new assigned probe.
 *
 * @param config Global nmap configuration.
 * @param worker Worker to inspect.
 *
 * @return 1 if the worker can accept one probe, 0 otherwise.
 */
static int	worker_can_accept(t_nmap_config *config, t_nmap_worker *worker)
{
	size_t	max_outstanding;

	if (worker->job_pending)
		return (0);
	max_outstanding = (size_t)config->scan.max_outstanding_per_worker;
	if (max_outstanding == 0)
		max_outstanding = 1;
	return (worker->outstanding_count < max_outstanding);
}

/**
 * @brief Assign one pending probe to an available worker.
 *
 * @param config Global nmap configuration.
 * @param probe Probe selected by the main scheduler.
 *
 * @return 1 when assigned, 0 when no worker can accept it now.
 *
 * @note Global scan capacity is checked by the scheduler before this function.
 *       Dispatch only reserves QUEUED state and worker ownership.
 */
int	nmap_dispatch_probe_to_sender(t_nmap_config *config, t_probe *probe)
{
	int				i;
	t_nmap_worker	*worker;

	if (!config || !probe || config->sender_pool.worker_count <= 0)
		return (0);
	i = 0;
	while (i < config->sender_pool.worker_count)
	{
		worker = &config->sender_pool.workers[i];
		pthread_mutex_lock(&config->sender_pool.runtime_lock);
		if (!config->sender_pool.stop_requested && probe->state == PROBE_PENDING
			&& worker_can_accept(config, worker))
		{
			probe->state = PROBE_QUEUED;
			probe->sender_id = worker->id;
			config->runtime.queued_count++;
			worker->job_pending = 1;
			if (probe_is_udp(probe))
			{
				config->runtime.udp_queued_count++;
				config->runtime.last_udp_dispatch_ms = get_time_ms();
			}
			pthread_mutex_unlock(&config->sender_pool.runtime_lock);
			pthread_mutex_lock(&worker->lock);
			worker->job = probe;
			pthread_cond_signal(&worker->cond);
			pthread_mutex_unlock(&worker->lock);
			return (1);
		}
		pthread_mutex_unlock(&config->sender_pool.runtime_lock);
		i++;
	}
	return (0);
}

/**
 * @brief Decrement the owner worker in-flight counter after DONE.
 *
 * @param config Global nmap configuration.
 * @param probe Probe that reached DONE.
 *
 * @note The caller already holds config->sender_pool.runtime_lock.
 */
void	nmap_sender_note_probe_done_locked(t_nmap_config *config,
		t_probe *probe)
{
	t_nmap_worker	*worker;

	if (!config || !probe)
		return ;
	if (probe->sender_id < 0 || probe->sender_id >= config->sender_pool.worker_count)
		return ;
	worker = &config->sender_pool.workers[probe->sender_id];
	if (worker->outstanding_count > 0)
		worker->outstanding_count--;
}
