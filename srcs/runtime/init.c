#include "config.h"
#include "runtime/runtime_internal.h"

#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/time.h>
#include <unistd.h>

#define NMAP_SOURCE_PORT_MIN 32768U

/** Count concrete scan types enabled in one scan mask. */
static size_t	count_scan_types(uint32_t mask)
{
	size_t	count;

	count = 0;
	if (mask & NMAP_SCAN_SYN)
		count++;
	if (mask & NMAP_SCAN_NULL)
		count++;
	if (mask & NMAP_SCAN_FIN)
		count++;
	if (mask & NMAP_SCAN_XMAS)
		count++;
	if (mask & NMAP_SCAN_ACK)
		count++;
	if (mask & NMAP_SCAN_UDP)
		count++;
	return (count);
}

/** Return the Nth concrete scan type in stable report order. */
static uint32_t	scan_type_at(uint32_t mask, size_t index)
{
	size_t	current;

	current = 0;
	if ((mask & NMAP_SCAN_SYN) && current++ == index)
		return (NMAP_SCAN_SYN);
	if ((mask & NMAP_SCAN_NULL) && current++ == index)
		return (NMAP_SCAN_NULL);
	if ((mask & NMAP_SCAN_FIN) && current++ == index)
		return (NMAP_SCAN_FIN);
	if ((mask & NMAP_SCAN_XMAS) && current++ == index)
		return (NMAP_SCAN_XMAS);
	if ((mask & NMAP_SCAN_ACK) && current++ == index)
		return (NMAP_SCAN_ACK);
	if ((mask & NMAP_SCAN_UDP) && current++ == index)
		return (NMAP_SCAN_UDP);
	return (0);
}

/**
 * @brief Fallback entropy when getrandom() cannot immediately provide bytes.
 */
static uint32_t	fallback_random(void)
{
	struct timeval	tv;
	uint32_t		value;

	gettimeofday(&tv, NULL);
	value = (uint32_t)tv.tv_sec ^ (uint32_t)tv.tv_usec;
	value ^= (uint32_t)getpid() * 0x9e3779b9U;
	value ^= value << 13;
	value ^= value >> 17;
	value ^= value << 5;
	return (value);
}

/** Return one best-effort random uint32_t for probe identity generation. */
static uint32_t	random_u32(void)
{
	uint32_t	value;
	ssize_t		ret;

	ret = getrandom(&value, sizeof(value), GRND_NONBLOCK);
	if (ret == (ssize_t)sizeof(value))
		return (value);
	return (fallback_random());
}

/**
 * @brief Choose one contiguous ephemeral source-port block for all probes.
 *
 * @note Source ports are unique inside the runtime and randomized between
 *       processes. This preserves O(1) lookup while reducing accidental cross
 *       matching when multiple scanner instances run simultaneously.
 */
static int	choose_source_port_base(t_nmap_runtime *runtime)
{
	uint32_t	max_base;
	uint32_t	span;

	if (runtime->probe_count == 0
		|| runtime->probe_count > 65535U - NMAP_SOURCE_PORT_MIN + 1U)
		return (0);
	max_base = 65535U - (uint32_t)runtime->probe_count + 1U;
	span = max_base - NMAP_SOURCE_PORT_MIN + 1U;
	runtime->source_port_base = (uint16_t)(NMAP_SOURCE_PORT_MIN
		+ random_u32() % span);
	return (1);
}

/** Insert a probe in the O(1) source-port candidate index. */
static int	index_probe(t_nmap_runtime *runtime, t_probe *probe)
{
	if (runtime->probe_by_src_port[probe->src_port])
		return (0);
	runtime->probe_by_src_port[probe->src_port] = probe;
	return (1);
}

/** Initialize one logical probe from the immutable scan plan. */
static int	init_probe(t_nmap_runtime *runtime, t_probe *probe,
		uint16_t dst_port, uint32_t scan_type, size_t index,
		uint32_t seq_seed)
{
	uint32_t	src_port;

	src_port = (uint32_t)runtime->source_port_base + (uint32_t)index;
	if (src_port > 65535U)
		return (0);
	memset(probe, 0, sizeof(*probe));
	probe->dst_port = dst_port;
	probe->src_port = (uint16_t)src_port;
	probe->seq = seq_seed + (uint32_t)index * 0x9e3779b9U;
	probe->scan_type = scan_type;
	probe->state = PROBE_PENDING;
	probe->result = SCAN_RESULT_UNKNOWN;
	return (index_probe(runtime, probe));
}

/** Fill the complete [port x scan-type] logical probe table. */
static int	fill_probes(t_nmap_config *config, size_t scan_count)
{
	size_t		port_index;
	size_t		scan_index;
	size_t		probe_index;
	uint32_t	scan_type;
	uint32_t	seq_seed;

	seq_seed = random_u32();
	probe_index = 0;
	port_index = 0;
	while (port_index < config->scan.port_count)
	{
		scan_index = 0;
		while (scan_index < scan_count)
		{
			scan_type = scan_type_at(config->scan.scan_mask, scan_index);
			if (!scan_type || !init_probe(&config->runtime,
					&config->runtime.probes[probe_index],
					config->scan.ports[port_index], scan_type,
					probe_index, seq_seed))
				return (0);
			probe_index++;
			scan_index++;
		}
		port_index++;
	}
	return (1);
}

/** Release a partially initialized runtime after setup failure. */
static void	cleanup_partial_runtime(t_nmap_runtime *runtime)
{
	free(runtime->probe_by_src_port);
	free(runtime->probes);
	if (runtime->probe_cond_initialized)
		pthread_cond_destroy(&runtime->probe_cond);
	if (runtime->lock_initialized)
		pthread_mutex_destroy(&runtime->lock);
	memset(runtime, 0, sizeof(*runtime));
}

/**
 * @brief Allocate and initialize the complete runtime for the current target.
 */
int	nmap_prepare_runtime(t_nmap_config *config, int *exit_status)
{
	size_t	scan_count;
	size_t	probe_count;

	if (!config)
		goto fail;
	memset(&config->runtime, 0, sizeof(config->runtime));
	if (pthread_mutex_init(&config->runtime.lock, NULL) != 0)
		goto fail;
	config->runtime.lock_initialized = 1;
	if (pthread_cond_init(&config->runtime.probe_cond, NULL) != 0)
		goto partial_fail;
	config->runtime.probe_cond_initialized = 1;
	nmap_timing_init(config);
	scan_count = count_scan_types(config->scan.scan_mask);
	if (config->scan.port_count == 0 || scan_count == 0)
		goto partial_fail;
	probe_count = config->scan.port_count * scan_count;
	config->runtime.probe_count = probe_count;
	if (!choose_source_port_base(&config->runtime))
		goto partial_fail;
	config->runtime.probes = calloc(probe_count, sizeof(t_probe));
	config->runtime.probe_by_src_port = calloc(65536, sizeof(t_probe *));
	if (!config->runtime.probes || !config->runtime.probe_by_src_port)
		goto partial_fail;
	if (!fill_probes(config, scan_count))
		goto partial_fail;
	return (1);
partial_fail:
	cleanup_partial_runtime(&config->runtime);
fail:
	if (exit_status)
		*exit_status = 1;
	return (0);
}

/**
 * @brief Check whether every logical probe reached DONE.
 */
int	nmap_runtime_is_finished(t_nmap_config *config)
{
	int	finished;

	if (!config || !config->runtime.lock_initialized)
		return (1);
	pthread_mutex_lock(&config->runtime.lock);
	finished = (config->runtime.done_count >= config->runtime.probe_count);
	pthread_mutex_unlock(&config->runtime.lock);
	return (finished);
}
