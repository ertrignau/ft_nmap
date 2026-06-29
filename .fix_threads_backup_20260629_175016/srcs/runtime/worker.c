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
 * @brief Mark a queued probe as in-flight immediately before sendto().
 *
 * @param worker Worker sending the probe.
 * @param probe Probe to mark.
 *
 * @return 1 if the probe may be sent, 0 if it was cancelled.
 *
 * @note The scheduler already counted this probe against global and per-worker
 *       in-flight limits. This function only starts the timeout clock and moves
 *       QUEUED to IN_FLIGHT.
 */
static int	mark_probe_sending(t_nmap_worker *worker, t_probe *probe)
{
	t_nmap_config	*config;

	config = worker->config;
	pthread_mutex_lock(&config->threads.state_lock);
	if (config->threads.stop || probe->state != PROBE_QUEUED)
	{
		pthread_mutex_unlock(&config->threads.state_lock);
		return (0);
	}
	probe->sent_at_ms = get_time_ms();
	probe->state = PROBE_IN_FLIGHT;
	pthread_mutex_unlock(&config->threads.state_lock);
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
	pthread_mutex_lock(&config->threads.state_lock);
	worker->busy = 0;
	pthread_mutex_unlock(&config->threads.state_lock);
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
	pthread_mutex_lock(&config->threads.state_lock);
	if (probe->state == PROBE_QUEUED || probe->state == PROBE_IN_FLIGHT)
	{
		probe->state = PROBE_DONE;
		probe->result = SCAN_RESULT_UNKNOWN;
		if (config->runtime.in_flight_count > 0)
			config->runtime.in_flight_count--;
		if (probe_is_udp(probe) && config->runtime.udp_in_flight_count > 0)
			config->runtime.udp_in_flight_count--;
		if (worker->in_flight_count > 0)
			worker->in_flight_count--;
		config->runtime.done_count++;
	}
	worker->busy = 0;
	config->threads.error = 1;
	pthread_mutex_unlock(&config->threads.state_lock);
}

/**
 * @brief Fetch the next assigned probe for a worker.
 *
 * @param worker Worker waiting for work.
 *
 * @return Assigned probe, or NULL when the worker must stop.
 */
static t_probe	*worker_wait_for_probe(t_nmap_worker *worker)
{
	t_probe	*probe;

	pthread_mutex_lock(&worker->lock);
	while (!worker->stop && !worker->probe)
		pthread_cond_wait(&worker->cond, &worker->lock);
	if (worker->stop && !worker->probe)
	{
		pthread_mutex_unlock(&worker->lock);
		return (NULL);
	}
	probe = worker->probe;
	worker->probe = NULL;
	pthread_mutex_unlock(&worker->lock);
	return (probe);
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
	t_probe			*probe;

	worker = (t_nmap_worker *)arg;
	while (1)
	{
		probe = worker_wait_for_probe(worker);
		if (!probe)
			break ;
		if (!mark_probe_sending(worker, probe))
		{
			mark_worker_available(worker);
			continue ;
		}
		DEBUG_PROBE_SEND(probe);
		if (!send_probe(worker->config, probe))
			mark_send_failed(worker, probe);
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
 * @param worker_id Worker index.
 *
 * @return 1 on success, 0 on pthread initialization failure.
 */
static int	init_worker(t_nmap_config *config, t_nmap_worker *worker,
		int worker_id)
{
	memset(worker, 0, sizeof(*worker));
	worker->config = config;
	worker->worker_id = worker_id;
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
 * @note The state lock is initialized even when speedup is 0 so cleanup and
 *       runtime helpers can stay simple.
 */
int	nmap_prepare_workers(t_nmap_config *config, int *exit_status)
{
	int	i;

	if (!config)
	{
		if (exit_status)
			*exit_status = 1;
		return (0);
	}
	memset(&config->threads, 0, sizeof(config->threads));
	if (pthread_mutex_init(&config->threads.state_lock, NULL) != 0)
	{
		if (exit_status)
			*exit_status = 1;
		return (0);
	}
	config->threads.initialized = 1;
	config->threads.worker_count = normalize_worker_count(config->cli.speedup);
	if (config->threads.worker_count == 0)
		return (1);
	config->threads.workers = calloc(config->threads.worker_count,
			sizeof(t_nmap_worker));
	if (!config->threads.workers)
	{
		if (exit_status)
			*exit_status = 1;
		return (0);
	}
	i = 0;
	while (i < config->threads.worker_count)
	{
		if (!init_worker(config, &config->threads.workers[i], i))
		{
			if (exit_status)
				*exit_status = 1;
			nmap_stop_workers(config);
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
void	nmap_stop_workers(t_nmap_config *config)
{
	int				i;
	t_nmap_worker	*worker;

	if (!config)
		return ;
	if (config->threads.workers)
	{
		i = 0;
		while (i < config->threads.worker_count)
		{
			worker = &config->threads.workers[i];
			pthread_mutex_lock(&worker->lock);
			worker->stop = 1;
			pthread_cond_signal(&worker->cond);
			pthread_mutex_unlock(&worker->lock);
			i++;
		}
		i = 0;
		while (i < config->threads.worker_count)
		{
			worker = &config->threads.workers[i];
			if (worker->started)
				pthread_join(worker->thread, NULL);
			pthread_cond_destroy(&worker->cond);
			pthread_mutex_destroy(&worker->lock);
			i++;
		}
		free(config->threads.workers);
		config->threads.workers = NULL;
	}
	if (config->threads.initialized)
	{
		pthread_mutex_destroy(&config->threads.state_lock);
		config->threads.initialized = 0;
	}
	config->threads.worker_count = 0;
}

/**
 * @brief Return whether a worker send error happened.
 *
 * @param config Global nmap configuration.
 *
 * @return 1 if a worker reported a fatal send error, 0 otherwise.
 */
int	nmap_workers_have_error(t_nmap_config *config)
{
	int	error;

	if (!config || !config->threads.initialized)
		return (0);
	pthread_mutex_lock(&config->threads.state_lock);
	error = config->threads.error;
	pthread_mutex_unlock(&config->threads.state_lock);
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
	size_t	max_per_thread;

	if (worker->busy)
		return (0);
	max_per_thread = (size_t)config->scan.max_in_flight_per_thread;
	if (max_per_thread == 0)
		max_per_thread = 1;
	return (worker->in_flight_count < max_per_thread);
}

/**
 * @brief Assign one pending probe to an available worker.
 *
 * @param config Global nmap configuration.
 * @param probe Probe selected by the main scheduler.
 *
 * @return 1 when assigned, 0 when no worker can accept it now.
 *
 * @note Assignment consumes global and per-worker capacity immediately. This
 *       prevents many queued UDP sends from bypassing the global UDP limits.
 */
int	nmap_dispatch_probe_to_worker(t_nmap_config *config, t_probe *probe)
{
	int				i;
	t_nmap_worker	*worker;

	if (!config || !probe || config->threads.worker_count <= 0)
		return (0);
	i = 0;
	while (i < config->threads.worker_count)
	{
		worker = &config->threads.workers[i];
		pthread_mutex_lock(&config->threads.state_lock);
		if (!config->threads.stop && probe->state == PROBE_PENDING
			&& worker_can_accept(config, worker))
		{
			probe->state = PROBE_QUEUED;
			probe->worker_id = worker->worker_id;
			config->runtime.in_flight_count++;
			worker->in_flight_count++;
			worker->busy = 1;
			if (probe_is_udp(probe))
				config->runtime.udp_in_flight_count++;
			pthread_mutex_unlock(&config->threads.state_lock);
			pthread_mutex_lock(&worker->lock);
			worker->probe = probe;
			pthread_cond_signal(&worker->cond);
			pthread_mutex_unlock(&worker->lock);
			return (1);
		}
		pthread_mutex_unlock(&config->threads.state_lock);
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
 * @note The caller already holds config->threads.state_lock.
 */
void	nmap_worker_note_probe_done_locked(t_nmap_config *config,
		t_probe *probe)
{
	t_nmap_worker	*worker;

	if (!config || !probe)
		return ;
	if (probe->worker_id < 0 || probe->worker_id >= config->threads.worker_count)
		return ;
	worker = &config->threads.workers[probe->worker_id];
	if (worker->in_flight_count > 0)
		worker->in_flight_count--;
}
