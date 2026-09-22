#include "ft_nmap.h"

int	parse_ttl(t_nmap_config *config, int argc, char **argv, int *i)
{
	int	ttl;

	if (!config || !argv || !i)
		return (0);
	if (*i + 1 >= argc)
	{
		fprintf(stderr, "ft_nmap: missing argument for --ttl\n");
		return (0);
	}
	if (config->cli.ttl_specified)
	{
		fprintf(stderr, "ft_nmap: --ttl specified more than once\n");
		return (0);
	}
	(*i)++;
	if (!nmap_parse_int(argv[*i], &ttl) || ttl < 0 || ttl > 255)
	{
		fprintf(stderr,
			"ft_nmap: invalid TTL value: %s (expected 0-255)\n",
			argv[*i]);
		return (0);
	}
	config->cli.ttl = ttl;
	config->cli.ttl_specified = 1;
	return (1);
}
