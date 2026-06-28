#!/usr/bin/env python3
from pathlib import Path
import re
import sys

ROOT = Path(".")


def die(msg):
    print(f"[tot.py] ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


def path(p):
    return ROOT / p


def read(p):
    f = path(p)
    if not f.exists():
        die(f"missing file: {p}")
    return f.read_text()


def write(p, content):
    f = path(p)
    backup = f.with_suffix(f.suffix + ".bak_profile")
    if f.exists() and not backup.exists():
        backup.write_text(f.read_text())
    f.write_text(content)


def replace_exact(p, old, new, label):
    content = read(p)
    if old not in content:
        die(f"{p}: pattern not found for {label}")
    content = content.replace(old, new, 1)
    write(p, content)


def replace_regex(p, pattern, repl, label, flags=re.S):
    content = read(p)
    new_content, count = re.subn(pattern, repl, content, count=1, flags=flags)
    if count != 1:
        die(f"{p}: regex pattern not found for {label}")
    write(p, new_content)


def ensure_contains_patch(p, marker, patch_func, label):
    content = read(p)
    if marker in content:
        print(f"[tot.py] skip {label}: already present")
        return
    new_content = patch_func(content)
    if new_content == content:
        die(f"{p}: patch did not change file for {label}")
    write(p, new_content)
    print(f"[tot.py] patched {label}")


def patch_makefile():
    p = "Makefile"
    content = read(p)

    if "PROFILE_OBJS_DIR := objs_profile" not in content:
        content = content.replace(
            "DEBUG_OBJS_DIR := objs_debug\n",
            "DEBUG_OBJS_DIR := objs_debug\n"
            "PROFILE_OBJS_DIR := objs_profile\n",
            1,
        )

    if "srcs/packet/link_offset.c" not in content:
        content = content.replace(
            "\t\tsrcs/packet/parse.c",
            "\t\tsrcs/packet/parse.c \\\n"
            "\t\tsrcs/packet/link_offset.c",
            1,
        )

    if "PROFILE_SRCS :=" not in content:
        content = content.replace(
            "DEBUG_SRCS :=\t$(SRCS) \\\n"
            "\t\t\t\tsrcs/debug/debug.c\n",
            "DEBUG_SRCS :=\t$(SRCS) \\\n"
            "\t\t\t\tsrcs/debug/debug.c\n\n"
            "PROFILE_SRCS :=\t$(SRCS) \\\n"
            "\t\t\t\tsrcs/debug/profilage.c\n",
            1,
        )

    if "PROFILE_OBJS :=" not in content:
        content = content.replace(
            "DEBUG_OBJS := $(patsubst %.c,$(DEBUG_OBJS_DIR)/%.o,$(DEBUG_SRCS))\n",
            "DEBUG_OBJS := $(patsubst %.c,$(DEBUG_OBJS_DIR)/%.o,$(DEBUG_SRCS))\n"
            "PROFILE_OBJS := $(patsubst %.c,$(PROFILE_OBJS_DIR)/%.o,$(PROFILE_SRCS))\n",
            1,
        )

    if "PROFILE_DEPS :=" not in content:
        content = content.replace(
            "DEBUG_DEPS := $(DEBUG_OBJS:.o=.d)\n",
            "DEBUG_DEPS := $(DEBUG_OBJS:.o=.d)\n"
            "PROFILE_DEPS := $(PROFILE_OBJS:.o=.d)\n",
            1,
        )

    if "profile: $(PROFILE_OBJS)" not in content:
        content = content.replace(
            "debug: $(DEBUG_OBJS)\n"
            "\t$(CC) $(CFLAGS) -DDEBUG $(DEBUG_OBJS) $(LDLIBS) -o $(NAME)\n",
            "debug: $(DEBUG_OBJS)\n"
            "\t$(CC) $(CFLAGS) -DDEBUG $(DEBUG_OBJS) $(LDLIBS) -o $(NAME)\n\n"
            "profile: $(PROFILE_OBJS)\n"
            "\t$(CC) $(CFLAGS) -DPROFILE $(PROFILE_OBJS) $(LDLIBS) -o $(NAME)\n",
            1,
        )

    if "$(PROFILE_OBJS_DIR)/%.o: %.c" not in content:
        content = content.replace(
            "$(DEBUG_OBJS_DIR)/%.o: %.c\n"
            "\t@mkdir -p $(dir $@)\n"
            "\t$(CC) $(CFLAGS) -DDEBUG $(CPPFLAGS) $(DEPFLAGS) -c $< -o $@\n",
            "$(DEBUG_OBJS_DIR)/%.o: %.c\n"
            "\t@mkdir -p $(dir $@)\n"
            "\t$(CC) $(CFLAGS) -DDEBUG $(CPPFLAGS) $(DEPFLAGS) -c $< -o $@\n\n"
            "$(PROFILE_OBJS_DIR)/%.o: %.c\n"
            "\t@mkdir -p $(dir $@)\n"
            "\t$(CC) $(CFLAGS) -DPROFILE $(CPPFLAGS) $(DEPFLAGS) -c $< -o $@\n",
            1,
        )

    if "$(RM) $(PROFILE_OBJS_DIR)" not in content:
        content = content.replace(
            "clean:\n"
            "\t$(RM) $(OBJS_DIR)\n"
            "\t$(RM) $(DEBUG_OBJS_DIR)\n",
            "clean:\n"
            "\t$(RM) $(OBJS_DIR)\n"
            "\t$(RM) $(DEBUG_OBJS_DIR)\n"
            "\t$(RM) $(PROFILE_OBJS_DIR)\n",
            1,
        )

    if "profile-run: profile" not in content:
        content = content.replace(
            "debug-run: debug\n"
            "\tsudo ./$(NAME)\n",
            "debug-run: debug\n"
            "\tsudo ./$(NAME)\n\n"
            "profile-run: profile\n"
            "\tsudo ./$(NAME)\n",
            1,
        )

    if "-include $(PROFILE_DEPS)" not in content:
        content = content.replace(
            "-include $(DEBUG_DEPS)\n",
            "-include $(DEBUG_DEPS)\n"
            "-include $(PROFILE_DEPS)\n",
            1,
        )

    content = content.replace(
        ".PHONY: all debug clean fclean re run debug-run",
        ".PHONY: all debug profile clean fclean re run debug-run profile-run",
    )

    write(p, content)
    print("[tot.py] patched Makefile")


def patch_debug_h():
    p = "srcs/debug/debug.h"

    profile_section = r'''# ifndef NMAP_PROFILING_SECTION
#  define NMAP_PROFILING_SECTION

typedef enum e_nmap_prof_event
{
	NMAP_PROF_SELECT_REQUESTED = 0,
	NMAP_PROF_SELECT_WAIT,
	NMAP_PROF_PCAP_NEXT_EX,
	NMAP_PROF_PACKET_PARSE_TOTAL,
	NMAP_PROF_LINK_OFFSET,
	NMAP_PROF_IPV4_PARSE,
	NMAP_PROF_TCP_PARSE,
	NMAP_PROF_UDP_PARSE,
	NMAP_PROF_ICMP_PARSE,
	NMAP_PROF_MATCH_PROBE,
	NMAP_PROF_CLASSIFY,
	NMAP_PROF_EXPIRE,
	NMAP_PROF_SEND_BUILD,
	NMAP_PROF_SEND_SENDTO,

	NMAP_PROF_PACKET_SEEN,
	NMAP_PROF_PACKET_PARSED,
	NMAP_PROF_PACKET_IGNORED,
	NMAP_PROF_PACKET_MATCHED,
	NMAP_PROF_PACKET_TIMEOUT,
	NMAP_PROF_PROBE_SENT,

	NMAP_PROF_EVENT_COUNT
}	t_nmap_prof_event;

#  ifdef PROFILE

uint64_t	nmap_prof_now_us(void);
void		nmap_prof_add(t_nmap_prof_event event, uint64_t start_us);
void		nmap_prof_add_value(t_nmap_prof_event event, uint64_t elapsed_us);
void		nmap_prof_count(t_nmap_prof_event event);
void		nmap_prof_report(void);

#   define PROF_START() nmap_prof_now_us()
#   define PROF_ADD(event, start_us) nmap_prof_add((event), (start_us))
#   define PROF_ADD_VALUE(event, elapsed_us) \
	nmap_prof_add_value((event), (elapsed_us))
#   define PROF_COUNT(event) nmap_prof_count((event))
#   define PROF_REPORT() nmap_prof_report()

#  else

#   define PROF_START() ((uint64_t)0)
#   define PROF_ADD(event, start_us) ((void)(event), (void)(start_us))
#   define PROF_ADD_VALUE(event, elapsed_us) \
	((void)(event), (void)(elapsed_us))
#   define PROF_COUNT(event) ((void)(event))
#   define PROF_REPORT() ((void)0)

#  endif

# endif
'''

    def apply(content):
        if "# include <stdint.h>" not in content:
            content = content.replace(
                "# include <stddef.h>\n",
                "# include <stddef.h>\n# include <stdint.h>\n",
                1,
            )
        return content.replace(
            "\n# ifdef DEBUG\n",
            "\n" + profile_section + "\n# ifdef DEBUG\n",
            1,
        )

    ensure_contains_patch(p, "NMAP_PROFILING_SECTION", apply, "debug.h profiling section")


def create_profilage_c():
    p = path("srcs/debug/profilage.c")
    if p.exists():
        print("[tot.py] skip srcs/debug/profilage.c: already exists")
        return

    content = r'''#include "debug/debug.h"

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
'''
    p.write_text(content)
    print("[tot.py] created srcs/debug/profilage.c")


def patch_main_c():
    p = "srcs/main.c"
    content = read(p)
    if "PROF_REPORT();" in content:
        print("[tot.py] skip main.c PROF_REPORT: already present")
        return
    content = content.replace(
        "\tnmap_print_report(&config);\n",
        "\tnmap_print_report(&config);\n\tPROF_REPORT();\n",
        1,
    )
    write(p, content)
    print("[tot.py] patched main.c")


def patch_wait_c():
    p = "srcs/runtime/wait.c"
    content = read(p)

    if '#include "debug/debug.h"' not in content:
        content = content.replace(
            '#include "config.h"\n',
            '#include "config.h"\n#include "debug/debug.h"\n',
            1,
        )

    old_time = r'''/**
 * @brief Return current time in milliseconds.
 *
 * @return Current timestamp in milliseconds.
 */
static uint64_t	get_time_ms(void)
{
	struct timeval	tv;

	gettimeofday(&tv, NULL);
	return ((uint64_t)tv.tv_sec * 1000 + (uint64_t)tv.tv_usec / 1000);
}
'''
    new_time = r'''/**
 * @brief Return current time in microseconds.
 *
 * @return Current timestamp in microseconds.
 */
static uint64_t	get_time_us(void)
{
	struct timeval	tv;

	gettimeofday(&tv, NULL);
	return ((uint64_t)tv.tv_sec * 1000000ULL + (uint64_t)tv.tv_usec);
}
'''
    if "static uint64_t\tget_time_us(void)" not in content:
        if old_time not in content:
            die("srcs/runtime/wait.c: get_time_ms block not found")
        content = content.replace(old_time, new_time, 1)

    content = content.replace(
        " * @param wait_ms Destination wait duration in milliseconds.\n",
        " * @param wait_ms Destination wait duration in milliseconds.\n"
        " * @param now_us Output timestamp used to compute this wait.\n",
        1,
    )

    content = content.replace(
        "static int\tget_next_timeout_ms(t_nmap_config *config, uint64_t *wait_ms)",
        "static int\tget_next_timeout_ms(t_nmap_config *config,\n"
        "\t\tuint64_t *wait_ms, uint64_t *now_us)",
        1,
    )

    content = content.replace(
        "\tnow_ms = get_time_ms();\n\tfound = 0;\n",
        "\tif (!now_us)\n\t\treturn (0);\n\t*now_us = get_time_us();\n"
        "\tnow_ms = *now_us / 1000;\n\tfound = 0;\n",
        1,
    )

    content = content.replace(
        "\tuint64_t\t\twait_ms;\n\tint\t\t\t\tret;\n",
        "\tuint64_t\t\twait_ms;\n\tuint64_t\t\tnow_us;\n\tuint64_t\t\tafter_us;\n"
        "\tint\t\t\t\tret;\n",
        1,
    )

    content = content.replace(
        "\tif (!get_next_timeout_ms(config, &wait_ms))\n",
        "\tif (!get_next_timeout_ms(config, &wait_ms, &now_us))\n",
        1,
    )

    if "NMAP_PROF_SELECT_WAIT" not in content:
        content = content.replace(
            "\tret = select(config->capture.fd + 1, &readfds, NULL, NULL, &timeout);\n",
            "\tret = select(config->capture.fd + 1, &readfds, NULL, NULL, &timeout);\n"
            "\tafter_us = get_time_us();\n"
            "\tPROF_ADD_VALUE(NMAP_PROF_SELECT_REQUESTED, wait_ms * 1000ULL);\n"
            "\tPROF_ADD_VALUE(NMAP_PROF_SELECT_WAIT, after_us - now_us);\n",
            1,
        )

    write(p, content)
    print("[tot.py] patched runtime/wait.c")


def patch_recv_c():
    p = "srcs/runtime/recv.c"
    content = read(p)

    if "NMAP_PROF_PACKET_PARSE_TOTAL" not in content:
        new_handle = r'''static int	handle_captured_packet(t_nmap_config *config,
		const unsigned char *packet, size_t len)
{
	t_nmap_reply	reply;
	t_probe			*probe;
	t_scan_result	result;
	uint64_t		prof_start;
	int				parsed;

	DEBUG_RECV_PACKET(packet, len);
	prof_start = PROF_START();
	parsed = nmap_parse_pcap_packet(config, packet, len, &reply);
	PROF_ADD(NMAP_PROF_PACKET_PARSE_TOTAL, prof_start);
	if (!parsed)
	{
		PROF_COUNT(NMAP_PROF_PACKET_IGNORED);
		return (0);
	}
	PROF_COUNT(NMAP_PROF_PACKET_PARSED);
	prof_start = PROF_START();
	probe = find_matching_probe(config, &reply);
	PROF_ADD(NMAP_PROF_MATCH_PROBE, prof_start);
	if (!probe)
	{
		PROF_COUNT(NMAP_PROF_PACKET_IGNORED);
		return (0);
	}
	prof_start = PROF_START();
	result = nmap_classify_reply(probe, &reply);
	PROF_ADD(NMAP_PROF_CLASSIFY, prof_start);
	if (result == SCAN_RESULT_UNKNOWN)
	{
		PROF_COUNT(NMAP_PROF_PACKET_IGNORED);
		return (0);
	}
	PROF_COUNT(NMAP_PROF_PACKET_MATCHED);
	mark_probe_done(config, probe, result);
	return (1);
}
'''
        content = re.sub(
            r'static int\thandle_captured_packet\(t_nmap_config \*config,.*?\n}\n\n/\*\*\n \* @brief Drain',
            new_handle + "\n/**\n * @brief Drain",
            content,
            count=1,
            flags=re.S,
        )

    if "\tuint64_t\t\t\tprof_start;\n" not in content:
        content = content.replace(
            "\tint\t\t\t\t\tret;\n",
            "\tint\t\t\t\t\tret;\n\tuint64_t\t\t\tprof_start;\n",
            1,
        )

    if "NMAP_PROF_PCAP_NEXT_EX" not in content:
        content = content.replace(
            "\t\tret = pcap_next_ex(config->capture.handle, &header, &packet);\n",
            "\t\tprof_start = PROF_START();\n"
            "\t\tret = pcap_next_ex(config->capture.handle, &header, &packet);\n"
            "\t\tPROF_ADD(NMAP_PROF_PCAP_NEXT_EX, prof_start);\n",
            1,
        )

    content = content.replace(
        "\t\tif (ret == 1)\n"
        "\t\t\thandle_captured_packet(config, packet, header->caplen);\n",
        "\t\tif (ret == 1)\n"
        "\t\t{\n"
        "\t\t\tPROF_COUNT(NMAP_PROF_PACKET_SEEN);\n"
        "\t\t\thandle_captured_packet(config, packet, header->caplen);\n"
        "\t\t}\n",
        1,
    )

    write(p, content)
    print("[tot.py] patched runtime/recv.c")


def patch_parse_c():
    p = "srcs/packet/parse.c"
    content = read(p)

    if '#include "debug/debug.h"' not in content:
        content = content.replace(
            '#include "config.h"\n',
            '#include "config.h"\n#include "debug/debug.h"\n',
            1,
        )

    content = content.replace("#define NMAP_ETHERNET_HEADER_LEN 14\n", "")

    content = re.sub(
        r'\n/\*\*\n \* @brief Return the layer 2 header length.*?static int\tget_ip_offset\(int datalink, size_t \*offset\).*?\n}\n\n/\*\*\n \* @brief Read',
        "\n/**\n * @brief Read",
        content,
        count=1,
        flags=re.S,
    )

    if "nmap_get_ipv4_offset" not in content:
        content = content.replace(
            "#define NMAP_ICMP_HEADER_LEN 8\n",
            "#define NMAP_ICMP_HEADER_LEN 8\n\n"
            "int\tnmap_get_ipv4_offset(int datalink, const unsigned char *packet,\n"
            "\t\tsize_t len, size_t *offset);\n",
            1,
        )

    new_tcp = r'''static int	parse_tcp_reply(const struct iphdr *ip, const unsigned char *packet,
		size_t len, size_t ip_offset, t_nmap_reply *reply)
{
	size_t				ip_header_len;
	size_t				tcp_offset;
	const unsigned char	*tcp;
	uint64_t			prof_start;

	prof_start = PROF_START();
	ip_header_len = (size_t)ip->ihl * 4;
	tcp_offset = ip_offset + ip_header_len;
	if (len < tcp_offset + NMAP_TCP_HEADER_MIN_LEN)
	{
		PROF_ADD(NMAP_PROF_TCP_PARSE, prof_start);
		return (0);
	}
	tcp = packet + tcp_offset;
	reply->type = NMAP_REPLY_TCP;
	reply->src_ip = ip->saddr;
	reply->dst_ip = ip->daddr;
	reply->src_port = read_u16(tcp);
	reply->dst_port = read_u16(tcp + 2);
	reply->tcp_flags = tcp[13];
	PROF_ADD(NMAP_PROF_TCP_PARSE, prof_start);
	return (1);
}
'''
    content = re.sub(
        r'static int\tparse_tcp_reply\(const struct iphdr \*ip,.*?\n}\n\n/\*\*\n \* @brief Parse a direct UDP reply',
        new_tcp + "\n/**\n * @brief Parse a direct UDP reply",
        content,
        count=1,
        flags=re.S,
    )

    new_udp = r'''static int	parse_udp_reply(const struct iphdr *ip, const unsigned char *packet,
		size_t len, size_t ip_offset, t_nmap_reply *reply)
{
	size_t				ip_header_len;
	size_t				udp_offset;
	const unsigned char	*udp;
	uint64_t			prof_start;

	prof_start = PROF_START();
	ip_header_len = (size_t)ip->ihl * 4;
	udp_offset = ip_offset + ip_header_len;
	if (len < udp_offset + NMAP_UDP_HEADER_LEN)
	{
		PROF_ADD(NMAP_PROF_UDP_PARSE, prof_start);
		return (0);
	}
	udp = packet + udp_offset;
	reply->type = NMAP_REPLY_UDP;
	reply->src_ip = ip->saddr;
	reply->dst_ip = ip->daddr;
	reply->src_port = read_u16(udp);
	reply->dst_port = read_u16(udp + 2);
	PROF_ADD(NMAP_PROF_UDP_PARSE, prof_start);
	return (1);
}
'''
    content = re.sub(
        r'static int\tparse_udp_reply\(const struct iphdr \*ip,.*?\n}\n\n/\*\*\n \* @brief Parse the embedded TCP/UDP header',
        new_udp + "\n/**\n * @brief Parse the embedded TCP/UDP header",
        content,
        count=1,
        flags=re.S,
    )

    new_icmp = r'''static int	parse_icmp_reply(const struct iphdr *ip, const unsigned char *packet,
		size_t len, size_t ip_offset, t_nmap_reply *reply)
{
	size_t				ip_header_len;
	size_t				icmp_offset;
	size_t				inner_ip_offset;
	const unsigned char	*icmp;
	const struct iphdr	*inner_ip;
	uint64_t			prof_start;
	int					ret;

	prof_start = PROF_START();
	ip_header_len = (size_t)ip->ihl * 4;
	icmp_offset = ip_offset + ip_header_len;
	if (len < icmp_offset + NMAP_ICMP_HEADER_LEN + sizeof(struct iphdr))
	{
		PROF_ADD(NMAP_PROF_ICMP_PARSE, prof_start);
		return (0);
	}
	icmp = packet + icmp_offset;
	inner_ip_offset = icmp_offset + NMAP_ICMP_HEADER_LEN;
	inner_ip = (const struct iphdr *)(packet + inner_ip_offset);
	if (inner_ip->version != 4 || inner_ip->ihl < 5)
	{
		PROF_ADD(NMAP_PROF_ICMP_PARSE, prof_start);
		return (0);
	}
	if (len < inner_ip_offset + ((size_t)inner_ip->ihl * 4))
	{
		PROF_ADD(NMAP_PROF_ICMP_PARSE, prof_start);
		return (0);
	}
	reply->type = NMAP_REPLY_ICMP;
	reply->src_ip = ip->saddr;
	reply->dst_ip = ip->daddr;
	reply->icmp_type = icmp[0];
	reply->icmp_code = icmp[1];
	ret = parse_icmp_original_transport(inner_ip, packet, len,
			inner_ip_offset, reply);
	PROF_ADD(NMAP_PROF_ICMP_PARSE, prof_start);
	return (ret);
}
'''
    content = re.sub(
        r'static int\tparse_icmp_reply\(const struct iphdr \*ip,.*?\n}\n\n/\*\*\n \* @brief Parse a raw pcap packet',
        new_icmp + "\n/**\n * @brief Parse a raw pcap packet",
        content,
        count=1,
        flags=re.S,
    )

    new_parse = r'''int	nmap_parse_pcap_packet(t_nmap_config *config, const unsigned char *packet,
		size_t len, t_nmap_reply *reply)
{
	size_t				ip_offset;
	const struct iphdr	*ip;
	size_t				ip_header_len;
	uint64_t			prof_start;

	if (!config || !packet || !reply)
		return (0);
	memset(reply, 0, sizeof(*reply));
	prof_start = PROF_START();
	if (!nmap_get_ipv4_offset(config->capture.datalink, packet,
			len, &ip_offset))
	{
		PROF_ADD(NMAP_PROF_LINK_OFFSET, prof_start);
		return (0);
	}
	PROF_ADD(NMAP_PROF_LINK_OFFSET, prof_start);
	prof_start = PROF_START();
	if (len < ip_offset + sizeof(struct iphdr))
	{
		PROF_ADD(NMAP_PROF_IPV4_PARSE, prof_start);
		return (0);
	}
	ip = (const struct iphdr *)(packet + ip_offset);
	if (ip->version != 4 || ip->ihl < 5)
	{
		PROF_ADD(NMAP_PROF_IPV4_PARSE, prof_start);
		return (0);
	}
	ip_header_len = (size_t)ip->ihl * 4;
	if (len < ip_offset + ip_header_len)
	{
		PROF_ADD(NMAP_PROF_IPV4_PARSE, prof_start);
		return (0);
	}
	PROF_ADD(NMAP_PROF_IPV4_PARSE, prof_start);
	if (ip->protocol == IPPROTO_TCP)
		return (parse_tcp_reply(ip, packet, len, ip_offset, reply));
	if (ip->protocol == IPPROTO_UDP)
		return (parse_udp_reply(ip, packet, len, ip_offset, reply));
	if (ip->protocol == IPPROTO_ICMP)
		return (parse_icmp_reply(ip, packet, len, ip_offset, reply));
	return (0);
}
'''
    content = re.sub(
        r'int\tnmap_parse_pcap_packet\(t_nmap_config \*config,.*?\n}\n\s*$',
        new_parse,
        content,
        count=1,
        flags=re.S,
    )

    write(p, content)
    print("[tot.py] patched packet/parse.c")


def patch_tcp_c():
    p = "srcs/packet/tcp.c"
    content = read(p)

    if "NMAP_PROF_SEND_BUILD" in content:
        print("[tot.py] skip tcp.c profiling: already present")
        return

    new_func = r'''int	nmap_send_tcp_probe(t_nmap_config *config, t_probe *probe)
{
	unsigned char		packet[sizeof(struct iphdr) + sizeof(struct tcphdr)];
	struct iphdr		*ip;
	struct tcphdr		*tcp;
	struct sockaddr_in	dst;
	size_t				packet_len;
	ssize_t				sent;
	uint64_t			prof_start;

	if (!config || !probe)
		return (0);
	prof_start = PROF_START();
	packet_len = sizeof(packet);
	memset(packet, 0, sizeof(packet));
	ip = (struct iphdr *)packet;
	tcp = (struct tcphdr *)(packet + sizeof(struct iphdr));
	build_ip_header(config, probe, ip, packet_len);
	if (!build_tcp_header(probe, tcp))
	{
		PROF_ADD(NMAP_PROF_SEND_BUILD, prof_start);
		fprintf(stderr, "ft_nmap: invalid TCP scan type: 0x%x\n",
			probe->scan_type);
		return (0);
	}
	set_tcp_checksum(config, probe, tcp);
	PROF_ADD(NMAP_PROF_SEND_BUILD, prof_start);
	memset(&dst, 0, sizeof(dst));
	dst.sin_family = AF_INET;
	dst.sin_addr.s_addr = probe->target_ip;
	dst.sin_port = htons(probe->dst_port);
	DEBUG_SEND_PACKET(packet, packet_len);
	prof_start = PROF_START();
	sent = sendto(config->socket.send_fd, packet, packet_len, 0,
			(struct sockaddr *)&dst, sizeof(dst));
	PROF_ADD(NMAP_PROF_SEND_SENDTO, prof_start);
	if (sent < 0 || (size_t)sent != packet_len)
	{
		perror("ft_nmap: sendto");
		return (0);
	}
	PROF_COUNT(NMAP_PROF_PROBE_SENT);
	return (1);
}
'''
    content = re.sub(
        r'int\tnmap_send_tcp_probe\(t_nmap_config \*config, t_probe \*probe\).*?\n}\n\s*$',
        new_func,
        content,
        count=1,
        flags=re.S,
    )
    write(p, content)
    print("[tot.py] patched packet/tcp.c")


def patch_expire_c():
    p = "srcs/runtime/expire.c"
    content = read(p)

    if "NMAP_PROF_PACKET_TIMEOUT" not in content:
        content = content.replace(
            '\tDEBUG_PROBE_TIMEOUT(probe);\n'
            '\tDEBUG_PROBE_RESULT(probe, "timeout");\n',
            '\tDEBUG_PROBE_TIMEOUT(probe);\n'
            '\tDEBUG_PROBE_RESULT(probe, "timeout");\n'
            '\tPROF_COUNT(NMAP_PROF_PACKET_TIMEOUT);\n',
            1,
        )

    if "NMAP_PROF_EXPIRE" not in content:
        content = content.replace(
            "\tsize_t\t\ti;\n\tuint64_t\tnow_ms;\n",
            "\tsize_t\t\ti;\n\tuint64_t\tnow_ms;\n\tuint64_t\tprof_start;\n",
            1,
        )
        content = content.replace(
            "\tnow_ms = get_time_ms();\n",
            "\tprof_start = PROF_START();\n\tnow_ms = get_time_ms();\n",
            1,
        )
        content = content.replace(
            "\twhile (i < config->runtime.probe_count)\n"
            "\t{\n"
            "\t\tif (probe_has_expired(&config->runtime.probes[i],\n"
            "\t\t\t\tnow_ms, config->scan.timeout_ms))\n"
            "\t\t\texpire_probe(config, &config->runtime.probes[i]);\n"
            "\t\ti++;\n"
            "\t}\n",
            "\twhile (i < config->runtime.probe_count)\n"
            "\t{\n"
            "\t\tif (probe_has_expired(&config->runtime.probes[i],\n"
            "\t\t\t\tnow_ms, config->scan.timeout_ms))\n"
            "\t\t\texpire_probe(config, &config->runtime.probes[i]);\n"
            "\t\ti++;\n"
            "\t}\n"
            "\tPROF_ADD(NMAP_PROF_EXPIRE, prof_start);\n",
            1,
        )

    write(p, content)
    print("[tot.py] patched runtime/expire.c")


def main():
    patch_makefile()
    patch_debug_h()
    create_profilage_c()
    patch_main_c()
    patch_wait_c()
    patch_recv_c()
    patch_parse_c()
    patch_tcp_c()
    patch_expire_c()
    print("[tot.py] done")
    print("[tot.py] next:")
    print("  make fclean")
    print("  make profile")
    print("  sudo ./ft_nmap 2> dump.txt")


if __name__ == "__main__":
    main()