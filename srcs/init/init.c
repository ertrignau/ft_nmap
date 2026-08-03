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
	config->cli.program_name = program_name;
	config->socket.send_fd = -1;
	config->capture.fd = -1;
	config->capture.datalink = -1;
	return (1);
}
