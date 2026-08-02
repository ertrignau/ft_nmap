#include "config.h"

int	nmap_init_config(t_nmap_config *config, const char *program_name,
		int *exit_status)
{
	if (!config)
	{
		if (exit_status)
			*exit_status = 1;
		return (0);
	}
	memset(config, 0, sizeof(*config));

	config->socket.send_fd = -1;
	config->capture.fd = -1;
	config->capture.datalink = -1;

	config->cli.program_name = program_name;

	config->scan.src_port_base = 40000;
	config->scan.tcp_timeout_ms = 1000;
	config->scan.udp_timeout_ms = 2500;
	config->scan.max_outstanding_per_worker = 1;
	config->scan.udp_max_in_flight = 10;
	config->scan.tcp_send_gap_ms = 0;
	config->scan.udp_dispatch_gap_ms = 50;
	return (1);
}