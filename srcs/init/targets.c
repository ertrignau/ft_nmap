#include "config.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

/** Release a partially prepared target list. */
static void	clear_targets(t_nmap_targets *targets)
{
	size_t	i;

	if (!targets)
		return ;
	i = 0;
	while (i < targets->count)
	{
		free(targets->items[i]);
		i++;
	}
	free(targets->items);
	memset(targets, 0, sizeof(*targets));
}

/** Return whether the exact target string is already present. */
static int	target_exists(const t_nmap_targets *targets, const char *value)
{
	size_t	i;

	i = 0;
	while (i < targets->count)
	{
		if (strcmp(targets->items[i], value) == 0)
			return (1);
		i++;
	}
	return (0);
}

/** Grow the owned target-pointer array while respecting the project limit. */
static int	grow_targets(t_nmap_targets *targets)
{
	char	**new_items;
	size_t	new_capacity;

	if (targets->capacity == 0)
		new_capacity = NMAP_TARGET_INITIAL_CAPACITY;
	else
	{
		new_capacity = targets->capacity * 2;
	}
	if (new_capacity > NMAP_MAX_TARGETS)
		new_capacity = NMAP_MAX_TARGETS;
	if (new_capacity <= targets->capacity)
		return (0);
	new_items = realloc(targets->items,
			new_capacity * sizeof(*new_items));
	if (!new_items)
		return (0);
	targets->items = new_items;
	targets->capacity = new_capacity;
	return (1);
}

/**
 * @brief Append one owned target string, silently ignoring duplicates.
 *
 * @note Target syntax is deliberately not restricted here. IPv4, IPv6,
 *       scoped IPv6 and hostnames are validated/resolved later by getaddrinfo.
 */
static int	add_target(t_nmap_targets *targets, const char *value)
{
	char	*copy;

	if (!value || value[0] == '\0')
		return (0);
	if (target_exists(targets, value))
		return (1);
	if (targets->count >= NMAP_MAX_TARGETS)
		return (0);
	if (targets->count == targets->capacity && !grow_targets(targets))
		return (0);
	copy = strdup(value);
	if (!copy)
		return (0);
	targets->items[targets->count] = copy;
	targets->count++;
	return (1);
}

/** Trim leading and trailing whitespace in place. */
static char	*trim_line(char *line)
{
	char	*start;
	char	*end;

	start = line;
	while (*start && isspace((unsigned char)*start))
		start++;
	end = start + strlen(start);
	while (end > start && isspace((unsigned char)end[-1]))
		end--;
	*end = '\0';
	return (start);
}

/** Load target strings from a file, with useful line-number diagnostics. */
static int	load_target_file(t_nmap_targets *targets, const char *path)
{
	FILE	*file;
	char	*line;
	char	*target;
	size_t	line_capacity;
	size_t	line_number;
	ssize_t	line_length;

	file = fopen(path, "r");
	if (!file)
	{
		fprintf(stderr, "ft_nmap: cannot open %s: %s\n",
			path, strerror(errno));
		return (0);
	}
	line = NULL;
	line_capacity = 0;
	line_number = 0;
	while (1)
	{
		errno = 0;
		line_length = getline(&line, &line_capacity, file);
		if (line_length < 0)
			break ;
		line_number++;
		target = trim_line(line);
		if (target[0] != '\0' && target[0] != '#'
			&& !add_target(targets, target))
		{
			fprintf(stderr, "ft_nmap: cannot add target at line %zu\n",
				line_number);
			free(line);
			fclose(file);
			return (0);
		}
	}
	free(line);
	if (ferror(file))
	{
		fprintf(stderr, "ft_nmap: error reading %s: %s\n",
			path, strerror(errno));
		fclose(file);
		return (0);
	}
	if (fclose(file) != 0)
	{
		fprintf(stderr, "ft_nmap: cannot close %s: %s\n",
			path, strerror(errno));
		return (0);
	}
	if (targets->count == 0)
	{
		fprintf(stderr, "ft_nmap: no valid targets in %s\n", path);
		return (0);
	}
	return (1);
}

/**
 * @brief Prepare an owned target list from the already validated CLI choice.
 */
int	nmap_prepare_targets(t_nmap_config *config, int *exit_status)
{
	int	success;

	if (!config)
		goto fail;
	memset(&config->targets, 0, sizeof(config->targets));
	if (config->cli.ip_specified)
		success = add_target(&config->targets, config->cli.target);
	else if (config->cli.file_specified)
		success = load_target_file(&config->targets, config->cli.target_file);
	else
	{
		success = 0;
	}
	if (success)
		return (1);
	clear_targets(&config->targets);
fail:
	if (exit_status)
		*exit_status = 1;
	return (0);
}
