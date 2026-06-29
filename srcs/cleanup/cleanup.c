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
	memset(config, 0, sizeof(*config));
	config->socket.send_fd = -1;
	config->capture.fd = -1;
	config->capture.datalink = -1;
}
