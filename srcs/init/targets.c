

#include "config.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

/**
 * @brief Release a partially prepared target list.
 *
 * @param targets Target list to clear.
 */
static void	clear_targets(t_nmap_targets *targets)
{
	size_t	index;

	if (!targets)
		return ;
	index = 0;
	while (index < targets->count)
	{
		free(targets->items[index]);
		index++;
	}
	free(targets->items);
	memset(targets, 0, sizeof(*targets));
}

/**
 * @brief Append one owned target string.
 *
 * @param targets Target list.
 * @param value Target text to copy.
 *
 * @return 1 on success, 0 on allocation failure.
 */
static int	add_target(t_nmap_targets *targets, const char *value)
{
	char	**new_items;
	char	*copy;
	size_t	new_capacity;

	if (targets->count == targets->capacity)
	{
		new_capacity = targets->capacity;
		if (new_capacity == 0)
			new_capacity = 8;
		else
			new_capacity *= 2;
		new_items = realloc(targets->items,
				new_capacity * sizeof(*new_items));
		if (!new_items)
			return (0);
		targets->items = new_items;
		targets->capacity = new_capacity;
	}
	copy = strdup(value);
	if (!copy)
		return (0);
	targets->items[targets->count] = copy;
	targets->count++;
	return (1);
}

/**
 * @brief Trim leading and trailing whitespace in place.
 *
 * @param line Mutable input line.
 *
 * @return Pointer to the first non-whitespace character.
 */
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

/**
 * @brief Load targets from one text file.
 *
 * @param targets Destination target list.
 * @param path File path supplied by the CLI.
 *
 * @return 1 on success, 0 on file or allocation failure.
 */
static int	load_target_file(t_nmap_targets *targets, const char *path)
{
	FILE	*file;
	char	*line;
	char	*target;
	size_t	line_capacity;
	ssize_t	line_length;

	file = fopen(path, "r");
	if (!file)
	{
		fprintf(stderr, "ft_nmap: %s: %s\n", path, strerror(errno));
		return (0);
	}
	line = NULL;
	line_capacity = 0;
	line_length = getline(&line, &line_capacity, file);
	while (line_length >= 0)
	{
		target = trim_line(line);
		if (target[0] != '\0' && target[0] != '#'
			&& !add_target(targets, target))
		{
			free(line);
			fclose(file);
			return (0);
		}
		line_length = getline(&line, &line_capacity, file);
	}
	free(line);
	if (ferror(file))
	{
		fprintf(stderr, "ft_nmap: %s: read error\n", path);
		fclose(file);
		return (0);
	}
	fclose(file);
	if (targets->count == 0)
	{
		fprintf(stderr, "ft_nmap: %s: no target found\n", path);
		return (0);
	}
	return (1);
}

/**
 * @brief Prepare an owned target list from --ip or --file.
 *
 * @param config Global nmap configuration.
 * @param exit_status Output exit status set on preparation failure.
 *
 * @return 1 on success, 0 on failure.
 */
int	nmap_prepare_targets(t_nmap_config *config, int *exit_status)
{
	int	has_target;
	int	has_file;
	int	success;

	if (!config)
	{
		if (exit_status)
			*exit_status = 1;
		return (0);
	}
	has_target = (config->cli.target && config->cli.target[0] != '\0');
	has_file = (config->cli.target_file
			&& config->cli.target_file[0] != '\0');
	if (has_target == has_file)
	{
		fprintf(stderr, "ft_nmap: provide exactly one of --ip or --file\n");
		if (exit_status)
			*exit_status = 1;
		return (0);
	}
	memset(&config->targets, 0, sizeof(config->targets));
	if (has_target)
		success = add_target(&config->targets, config->cli.target);
	else
		success = load_target_file(&config->targets, config->cli.target_file);
	if (!success)
	{
		clear_targets(&config->targets);
		if (exit_status)
			*exit_status = 1;
		return (0);
	}
	return (1);
}
