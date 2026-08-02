#include "ft_nmap.h"

int	scan_name_to_mask(const char *name, uint32_t *mask)
{
	if (nmap_streq(name, "SYN"))
		*mask = NMAP_SCAN_SYN;
	else if (nmap_streq(name, "NULL"))
		*mask = NMAP_SCAN_NULL;
	else if (nmap_streq(name, "FIN"))
		*mask = NMAP_SCAN_FIN;
	else if (nmap_streq(name, "XMAS"))
		*mask = NMAP_SCAN_XMAS;
	else if (nmap_streq(name, "ACK"))
		*mask = NMAP_SCAN_ACK;
	else if (nmap_streq(name, "UDP"))
		*mask = NMAP_SCAN_UDP;
	else
		return (0);
	return (1);
}

int	parse_scan(t_nmap_config *config, int argc, char **argv, int *i)
{
	uint32_t	mask;

	if (!config || !argv || !i)
		return (0);
	if (*i + 1 >= argc)
	{
		fprintf(stderr, "ft_nmap: missing argument for --scan\n");
		return (0);
	}
	if (config->cli.scan_specified)
	{
		fprintf(stderr, "ft_nmap: --scan specified more than once\n");
		return (0);
	}
	(*i)++;
	mask = 0;
	if (!scan_name_to_mask(argv[*i], &mask))
	{
		fprintf(stderr, "ft_nmap: invalid scan type: %s\n", argv[*i]);
		return (0);
	}
	config->cli.scan_mask = mask;
	config->cli.scan_specified = 1;
	return (1);
}