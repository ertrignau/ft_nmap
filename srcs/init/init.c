#include "config.h"

#include <string.h>

/**
 * @brief Initialize global process state and invalid file-descriptor sentinels.
 *
 * @param config Global nmap configuration.
 * @param program_name Executable name received from argv[0].
 * @param exit_status Output status set on invalid input.
 *
 * @return 1 on success, 0 on failure.
 *
 * @note Effective scan defaults are intentionally applied later by
 *       nmap_prepare_scan_config().
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
