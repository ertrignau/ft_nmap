
#include "config.h"
#include "runtime/worker.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pcap/pcap.h>

/**
 * @brief Release resources owned by the current target scan.
 *
 * @param config Global nmap configuration.
 *
 * @note The raw send socket and the owned target list are global resources and
 *       remain available for the next target.
 */
void	nmap_cleanup_current_target(t_nmap_config *config)
{
	if (!config)
		return ;
	nmap_stop_sender_pool(config);
	if (config->capture.handle)
		pcap_close(config->capture.handle);
	if (config->runtime.probe_by_src_port)
		free(config->runtime.probe_by_src_port);
	if (config->runtime.probes)
		free(config->runtime.probes);
	memset(&config->target, 0, sizeof(config->target));
	memset(&config->route, 0, sizeof(config->route));
	memset(&config->capture, 0, sizeof(config->capture));
	memset(&config->runtime, 0, sizeof(config->runtime));
	memset(&config->sender_pool, 0, sizeof(config->sender_pool));
	config->capture.fd = -1;
	config->capture.datalink = -1;
}

/**
 * @brief Release every resource owned by the full program.
 *
 * @param config Global nmap configuration.
 */
void	nmap_cleanup_config(t_nmap_config *config)
{
	size_t	index;

	if (!config)
		return ;
	nmap_cleanup_current_target(config);
	if (config->socket.send_fd >= 0)
		close(config->socket.send_fd);
	index = 0;
	while (index < config->targets.count)
	{
		free(config->targets.items[index]);
		index++;
	}
	free(config->targets.items);
	memset(config, 0, sizeof(*config));
	config->socket.send_fd = -1;
	config->capture.fd = -1;
	config->capture.datalink = -1;
}
