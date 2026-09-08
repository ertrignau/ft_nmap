/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   parsing_utils.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: eric <eric@student.42.fr>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2026/06/30 08:32:39 by eric              #+#    #+#             */
/*   Updated: 2026/06/30 08:43:30 by eric             ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"
#include <stdlib.h>
#include <string.h>

int	nmap_streq(const char *a, const char *b)
{
	if (!a || !b)
		return (0);
	return (strcmp(a, b) == 0);
}

int	nmap_parse_int(const char *s, int *out)
{
	long	value;
	char	*end;

	if (!s || !out)
		return (0);
	value = strtol(s, &end, 10);
	if (*end != '\0')
		return (0);
	if (value < 0 || value > 65535)
		return (0);
	*out = (int)value;
	return (1);
}
