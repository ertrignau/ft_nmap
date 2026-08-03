#include <stdlib.h>
#include "config.h"
#include "runtime/worker.h"

#include <string.h>
#include <unistd.h>
#include <pcap/pcap.h>

void	nmap_cleanup_config(t_nmap_config *config)
{
	if (!config)
		return ;
	nmap_stop_sender_pool(config);
	if (config->socket.send_fd >= 0)
		close(config->socket.send_fd);
	if (config->capture.handle)
		pcap_close(config->capture.handle);
	if (config->runtime.probe_by_src_port)
		free(config->runtime.probe_by_src_port);
	if (config->runtime.probes)
		free(config->runtime.probes);
	if (config->targets.items)
		free(config->targets.items);
	memset(config, 0, sizeof(*config));
	config->socket.send_fd = -1;
	config->capture.fd = -1;
	config->capture.datalink = -1;
}

//	Fonction de cleanup du file
void	nmap_cleanup_target_scan(t_nmap_config *config)
{
	if (!config)
		return ;
	nmap_stop_sender_pool(config);
	if (config->socket.send_fd >= 0)
		close(config->socket.send_fd);
	if (config->capture.handle)
		pcap_close(config->capture.handle);
	free(config->runtime.probe_by_src_port);
	free(config->runtime.probes);

	memset(&config->target, 0, sizeof(config->target));
	memset(&config->route, 0, sizeof(config->route));
	memset(&config->socket, 0, sizeof(config->socket));
	memset(&config->capture, 0, sizeof(config->capture));
	memset(&config->runtime, 0, sizeof(config->runtime));
	memset(&config->sender_pool, 0, sizeof(config->sender_pool));

	config->socket.send_fd = -1;
	config->capture.fd = -1;
	config->capture.datalink = -1;
}