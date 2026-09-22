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

#include <limits.h>
#include <string.h>

int	nmap_streq(const char *a, const char *b)
{
	if (!a || !b)
		return (0);
	return (strcmp(a, b) == 0);
}

int	nmap_parse_int(const char *s, int *out)
{
	unsigned long	value;
	unsigned int	digit;
	size_t			i;

	if (!s || !out || s[0] == '\0')
		return (0);
	value = 0;
	i = 0;
	while (s[i] != '\0')
	{
		if (s[i] < '0' || s[i] > '9')
			return (0);
		digit = (unsigned int)(s[i] - '0');
		if (value > ((unsigned long)INT_MAX - digit) / 10UL)
			return (0);
		value = value * 10UL + digit;
		i++;
	}
	*out = (int)value;
	return (1);
}
