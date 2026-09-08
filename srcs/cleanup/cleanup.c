#include "config.h"
#include "runtime/worker.h"

#include <pcap/pcap.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/**
 * @brief Release allocations and synchronization state owned by the runtime.
 */
static void	cleanup_runtime(t_nmap_runtime *runtime)
{
	if (!runtime)
		return ;
	free(runtime->probe_by_src_port);
	free(runtime->probes);
	if (runtime->probe_cond_initialized)
		pthread_cond_destroy(&runtime->probe_cond);
	if (runtime->lock_initialized)
		pthread_mutex_destroy(&runtime->lock);
	memset(runtime, 0, sizeof(*runtime));
}

/**
 * @brief Release resources owned by the current resolved target.
 *
 * @note Unlike the old IPv4-only design, the raw socket is target-scoped: its
 *       address family depends on the current resolved target.
 */
void	nmap_cleanup_current_target(t_nmap_config *config)
{
	if (!config)
		return ;
	nmap_stop_sender_pool(config);
	if (config->capture.handle)
		pcap_close(config->capture.handle);
	if (config->socket.send_fd >= 0)
		close(config->socket.send_fd);
	cleanup_runtime(&config->runtime);
	memset(&config->target, 0, sizeof(config->target));
	memset(&config->route, 0, sizeof(config->route));
	memset(&config->socket, 0, sizeof(config->socket));
	memset(&config->capture, 0, sizeof(config->capture));
	memset(&config->sender_pool, 0, sizeof(config->sender_pool));
	config->socket.send_fd = -1;
	config->capture.fd = -1;
	config->capture.datalink = -1;
}

/**
 * @brief Release all process-owned resources.
 */
void	nmap_cleanup_config(t_nmap_config *config)
{
	size_t	i;

	if (!config)
		return ;
	nmap_cleanup_current_target(config);
	i = 0;
	while (i < config->targets.count)
	{
		free(config->targets.items[i]);
		i++;
	}
	free(config->targets.items);
	memset(config, 0, sizeof(*config));
	config->socket.send_fd = -1;
	config->capture.fd = -1;
	config->capture.datalink = -1;
}
