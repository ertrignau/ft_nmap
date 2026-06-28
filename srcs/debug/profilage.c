#include "debug/debug.h"

#ifdef PROFILE

# include <stdio.h>
# include <sys/time.h>

typedef struct s_prof_slot
{
	const char	*name;
	uint64_t	calls;
	uint64_t	total_us;
	uint64_t	min_us;
	uint64_t	max_us;
}	t_prof_slot;

static t_prof_slot	g_prof[NMAP_PROF_EVENT_COUNT] = {
	[NMAP_PROF_SELECT_REQUESTED] = {"select requested", 0, 0, 0, 0},
	[NMAP_PROF_SELECT_WAIT] = {"select wait", 0, 0, 0, 0},
	[NMAP_PROF_PCAP_NEXT_EX] = {"pcap_next_ex", 0, 0, 0, 0},
	[NMAP_PROF_PACKET_PARSE_TOTAL] = {"packet parse total", 0, 0, 0, 0},
	[NMAP_PROF_LINK_OFFSET] = {"link offset", 0, 0, 0, 0},
	[NMAP_PROF_IPV4_PARSE] = {"ipv4 parse", 0, 0, 0, 0},
	[NMAP_PROF_TCP_PARSE] = {"tcp parse", 0, 0, 0, 0},
	[NMAP_PROF_UDP_PARSE] = {"udp parse", 0, 0, 0, 0},
	[NMAP_PROF_ICMP_PARSE] = {"icmp parse", 0, 0, 0, 0},
	[NMAP_PROF_MATCH_PROBE] = {"match probe", 0, 0, 0, 0},
	[NMAP_PROF_CLASSIFY] = {"classify", 0, 0, 0, 0},
	[NMAP_PROF_EXPIRE] = {"expire", 0, 0, 0, 0},
	[NMAP_PROF_SEND_BUILD] = {"send build", 0, 0, 0, 0},
	[NMAP_PROF_SEND_SENDTO] = {"sendto", 0, 0, 0, 0},

	[NMAP_PROF_PACKET_SEEN] = {"packets seen", 0, 0, 0, 0},
	[NMAP_PROF_PACKET_PARSED] = {"packets parsed", 0, 0, 0, 0},
	[NMAP_PROF_PACKET_IGNORED] = {"packets ignored", 0, 0, 0, 0},
	[NMAP_PROF_PACKET_MATCHED] = {"packets matched", 0, 0, 0, 0},
	[NMAP_PROF_PACKET_TIMEOUT] = {"probe timeouts", 0, 0, 0, 0},
	[NMAP_PROF_PROBE_SENT] = {"probes sent", 0, 0, 0, 0},
};

uint64_t	nmap_prof_now_us(void)
{
	struct timeval	tv;

	gettimeofday(&tv, NULL);
	return ((uint64_t)tv.tv_sec * 1000000ULL + (uint64_t)tv.tv_usec);
}

void	nmap_prof_add_value(t_nmap_prof_event event, uint64_t elapsed_us)
{
	t_prof_slot	*slot;

	if ((int)event < 0 || event >= NMAP_PROF_EVENT_COUNT)
		return ;
	slot = &g_prof[event];
	slot->calls++;
	slot->total_us += elapsed_us;
	if (slot->calls == 1 || elapsed_us < slot->min_us)
		slot->min_us = elapsed_us;
	if (elapsed_us > slot->max_us)
		slot->max_us = elapsed_us;
}

void	nmap_prof_add(t_nmap_prof_event event, uint64_t start_us)
{
	nmap_prof_add_value(event, nmap_prof_now_us() - start_us);
}

void	nmap_prof_count(t_nmap_prof_event event)
{
	t_prof_slot	*slot;

	if ((int)event < 0 || event >= NMAP_PROF_EVENT_COUNT)
		return ;
	slot = &g_prof[event];
	slot->calls++;
}

static void	print_timed_slot(const t_prof_slot *slot)
{
	double	total_ms;
	double	avg_us;

	if (slot->calls == 0)
		return ;
	total_ms = (double)slot->total_us / 1000.0;
	avg_us = (double)slot->total_us / (double)slot->calls;
	fprintf(stderr,
		"[profile] %-20s calls=%-8llu total=%10.3f ms avg=%10.3f us min=%-8llu max=%-8llu\n",
		slot->name,
		(unsigned long long)slot->calls,
		total_ms,
		avg_us,
		(unsigned long long)slot->min_us,
		(unsigned long long)slot->max_us);
}

static void	print_counter_slot(const t_prof_slot *slot)
{
	if (slot->calls == 0)
		return ;
	fprintf(stderr,
		"[profile] %-20s count=%llu\n",
		slot->name,
		(unsigned long long)slot->calls);
}

void	nmap_prof_report(void)
{
	int	i;

	fprintf(stderr, "\n[profile] ===== ft_nmap profiling report =====\n");
	i = 0;
	while (i < NMAP_PROF_EVENT_COUNT)
	{
		if (i >= NMAP_PROF_PACKET_SEEN)
			print_counter_slot(&g_prof[i]);
		else
			print_timed_slot(&g_prof[i]);
		i++;
	}
	fprintf(stderr, "[profile] ====================================\n");
}

#endif
