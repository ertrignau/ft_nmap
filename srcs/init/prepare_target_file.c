/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   prepare_target_file.c                              :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: eric <eric@student.42.fr>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2026/08/03 13:41:09 by eric              #+#    #+#             */
/*   Updated: 2026/08/03 13:42:06 by eric             ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

# include "ft_nmap.h"

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

static int	target_syntax_is_valid(const char *target)
{
	size_t	i;

	if (!target || target[0] == '\0')
		return (0);
	if (strlen(target) >= NMAP_HOSTNAME_SIZE)
		return (0);
	i = 0;
	while (target[i])
	{
		if (!isalnum((unsigned char)target[i])
			&& target[i] != '.'
			&& target[i] != '-'
			&& target[i] != '_')
			return (0);
		i++;
	}
	return (1);
}

static int	target_already_exists(t_nmap_target_list *list,
		const char *target)
{
	size_t	i;

	i = 0;
	while (i < list->count)
	{
		if (strcmp(list->items[i].hostname, target) == 0)
			return (1);
		i++;
	}
	return (0);
}

static int	grow_target_list(t_nmap_target_list *list)
{
	t_nmap_target_entry	*new_items;
	size_t				new_capacity;

	if (list->capacity == 0)
		new_capacity = NMAP_TARGET_INITIAL_CAPACITY;
	else
		new_capacity = list->capacity * 2;
	if (new_capacity > NMAP_MAX_TARGETS)
		new_capacity = NMAP_MAX_TARGETS;
	if (new_capacity <= list->capacity)
		return (0);
	new_items = realloc(list->items,
			new_capacity * sizeof(t_nmap_target_entry));
	if (!new_items)
		return (0);
	list->items = new_items;
	list->capacity = new_capacity;
	return (1);
}

static int	add_target(t_nmap_target_list *list, const char *target)
{
	t_nmap_target_entry	*entry;

	if (target_already_exists(list, target))
		return (1);
	if (list->count >= NMAP_MAX_TARGETS)
		return (0);
	if (list->count == list->capacity && !grow_target_list(list))
		return (0);
	entry = &list->items[list->count];
	memset(entry, 0, sizeof(*entry));
	memcpy(entry->hostname, target, strlen(target) + 1);
	list->count++;
	return (1);
}

static int	parse_target_line(t_nmap_config *config, char *line,
		size_t line_number)
{
	char	*target;

	target = trim_line(line);
	if (target[0] == '\0' || target[0] == '#')
		return (1);
	if (!target_syntax_is_valid(target))
	{
		fprintf(stderr,
			"ft_nmap: invalid target at line %zu: %s\n",
			line_number, target);
		return (0);
	}
	if (!add_target(&config->targets, target))
	{
		fprintf(stderr,
			"ft_nmap: cannot add target at line %zu\n",
			line_number);
		return (0);
	}
	return (1);
}

static int	read_target_file(t_nmap_config *config, FILE *file)
{
	char	*line;
	size_t	line_capacity;
	ssize_t	line_length;
	size_t	line_number;

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
		if (!parse_target_line(config, line, line_number))
		{
			free(line);
			return (0);
		}
	}
	free(line);
	if (ferror(file))
	{
		fprintf(stderr, "ft_nmap: error reading %s: %s\n",
			config->cli.file_path, strerror(errno));
		return (0);
	}
	return (1);
}

int	nmap_prepare_target_file(t_nmap_config *config, int *exit_status)
{
	FILE	*file;
	int		success;

	if (!config || !config->cli.file_path
		|| config->cli.file_path[0] == '\0')
	{
		if (exit_status)
			*exit_status = 1;
		return (0);
	}
	file = fopen(config->cli.file_path, "r");
	if (!file)
	{
		fprintf(stderr, "ft_nmap: cannot open %s: %s\n",
			config->cli.file_path, strerror(errno));
		if (exit_status)
			*exit_status = 1;
		return (0);
	}
	success = read_target_file(config, file);
	if (fclose(file) != 0)
	{
		fprintf(stderr, "ft_nmap: cannot close %s: %s\n",
			config->cli.file_path, strerror(errno));
		success = 0;
	}
	if (!success || config->targets.count == 0)
	{
		if (config->targets.count == 0)
			fprintf(stderr, "ft_nmap: no valid targets in %s\n",
				config->cli.file_path);
		if (exit_status)
			*exit_status = 1;
		return (0);
	}
	return (1);
}
