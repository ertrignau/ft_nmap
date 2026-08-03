/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   pars_scan.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: eric <eric@student.42.fr>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2026/08/03 16:02:14 by eric              #+#    #+#             */
/*   Updated: 2026/08/03 16:04:23 by eric             ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

int	scan_name_to_mask(const char *name, uint32_t *mask)
{
	if (!name || !mask)
		return (0);
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

static int	scan_list_is_valid(const char *arg)
{
	size_t	i;

	if (!arg || arg[0] == '\0')
		return (0);
	if (arg[0] == ',' || arg[strlen(arg) - 1] == ',')
		return (0);
	i = 0;
	while (arg[i])
	{
		if (arg[i] == ',' && arg[i + 1] == ',')
			return (0);
		i++;
	}
	return (1);
}

static int	parse_scan_list(const char *arg, uint32_t *scan_mask)
{
	char		*copy;
	char		*token;
	char		*saveptr;
	uint32_t	mask;

	if (!scan_list_is_valid(arg))
		return (0);
	copy = strdup(arg);
	if (!copy)
		return (0);
	*scan_mask = 0;
	token = strtok_r(copy, ",", &saveptr);
	while (token)
	{
		mask = 0;
		if (!scan_name_to_mask(token, &mask))
		{
			free(copy);
			return (0);
		}
		*scan_mask |= mask;
		token = strtok_r(NULL, ",", &saveptr);
	}
	free(copy);
	return (*scan_mask != 0);
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
	if (!parse_scan_list(argv[*i], &mask))
	{
		fprintf(stderr, "ft_nmap: invalid scan type list: %s\n",
			argv[*i]);
		return (0);
	}
	config->cli.scan_arg = argv[*i];
	config->cli.scan_mask = mask;
	config->cli.scan_specified = 1;
	return (1);
}
