
#include "config.h"

#include <string.h>

/**
 * @brief Initialize the global configuration and resource sentinels.
 *
 * @param config Global nmap configuration.
 * @param program_name Executable name received from argv[0].
 * @param exit_status Output exit status set on invalid input.
 *
 * @return 1 on success, 0 on failure.
 *
 * @note This is the only global memset of the configuration. Effective scan
 *       defaults are applied later by nmap_prepare_scan_config().
 */
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
	return (1);
}
