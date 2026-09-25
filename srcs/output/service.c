#include "output/output_internal.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>


/*
 * Service-name cache.
 *
 * Prefer Nmap's own port-name database, so SERVICE matches an installed Nmap.
 * Use the system services database when nmap-services is unavailable.
 */
#define NMAP_SERVICE_CACHE_CHUNK 64
#define NMAP_SERVICE_CACHE_NAME_MAX 64

typedef struct s_nmap_service_cache_entry
{
	int		port;
	char	proto[4];
	char	name[NMAP_SERVICE_CACHE_NAME_MAX];
}	t_nmap_service_cache_entry;

static t_nmap_service_cache_entry	*g_service_cache;
static size_t						g_service_cache_count;
static size_t						g_service_cache_capacity;
static int							g_service_cache_loaded;
/* The entry index is offset by one so zero means no name for that port. */
static size_t						g_service_index[2][65536];

/**
 * @brief Release the process-wide service-name cache.
 */
static void	nmap_service_cache_cleanup(void)
{
	free(g_service_cache);
	g_service_cache = NULL;
	g_service_cache_count = 0;
	g_service_cache_capacity = 0;
	g_service_cache_loaded = 0;
	memset(g_service_index, 0, sizeof(g_service_index));
}

/**
 * @brief Grow the service-name cache when necessary.
 */
static int	nmap_service_cache_reserve(void)
{
	t_nmap_service_cache_entry	*entries;
	size_t						capacity;

	if (g_service_cache_count < g_service_cache_capacity)
		return (1);
	capacity = g_service_cache_capacity + NMAP_SERVICE_CACHE_CHUNK;
	entries = realloc(g_service_cache,
			capacity * sizeof(*g_service_cache));
	if (!entries)
		return (0);
	g_service_cache = entries;
	g_service_cache_capacity = capacity;
	return (1);
}

/**
 * @brief Store one service database entry in the in-memory cache.
 */
static int	nmap_service_cache_add(const struct servent *service)
{
	t_nmap_service_cache_entry	*entry;

	if (!service || !service->s_name || !service->s_proto)
		return (1);
	if (strcmp(service->s_proto, "tcp") != 0
		&& strcmp(service->s_proto, "udp") != 0)
		return (1);
	if (!nmap_service_cache_reserve())
		return (0);
	entry = &g_service_cache[g_service_cache_count];
	entry->port = service->s_port;
	strncpy(entry->proto, service->s_proto, sizeof(entry->proto) - 1);
	entry->proto[sizeof(entry->proto) - 1] = '\0';
	strncpy(entry->name, service->s_name, sizeof(entry->name) - 1);
	entry->name[sizeof(entry->name) - 1] = '\0';
	if (!g_service_index[strcmp(entry->proto, "tcp") != 0]
			[ntohs((uint16_t)entry->port)])
		g_service_index[strcmp(entry->proto, "tcp") != 0]
			[ntohs((uint16_t)entry->port)] = g_service_cache_count + 1;
	g_service_cache_count++;
	return (1);
}

/** Read Nmap's "name port/protocol frequency" format into the same cache. */
static int	nmap_service_cache_read_nmap(FILE *file)
{
	char		line[512];
	char		name[NMAP_SERVICE_CACHE_NAME_MAX];
	char		proto[4];
	unsigned int	port;
	struct servent	service;

	while (fgets(line, sizeof(line), file))
	{
		if (sscanf(line, "%63s %u/%3s", name, &port, proto) != 3
			|| port > 65535)
			continue ;
		service.s_name = name;
		service.s_proto = proto;
		service.s_port = htons((uint16_t)port);
		if (!nmap_service_cache_add(&service))
			return (0);
	}
	return (g_service_cache_count != 0);
}

/** Search the installed Nmap data directories, including NMAPDIR. */
static int	nmap_service_cache_load_nmap(void)
{
	const char	*paths[] = {"/usr/share/nmap/nmap-services",
		"/usr/local/share/nmap/nmap-services", NULL};
	const char	*dir;
	char		path[4096];
	FILE		*file;
	int			i;
	int			loaded;

	dir = getenv("NMAPDIR");
	if (dir && snprintf(path, sizeof(path), "%s/nmap-services", dir)
		< (int)sizeof(path))
	{
		file = fopen(path, "r");
		if (file)
		{
			loaded = nmap_service_cache_read_nmap(file);
			fclose(file);
			return (loaded);
		}
	}
	i = 0;
	while (paths[i])
	{
		file = fopen(paths[i], "r");
		if (file)
		{
			loaded = nmap_service_cache_read_nmap(file);
			fclose(file);
			return (loaded);
		}
		i++;
	}
	return (0);
}

/**
 * @brief Load Nmap's service names, or fall back to system names.
 *
 * setservent(1) asks libc to keep the service database open while getservent()
 * walks it. All TCP/UDP names are copied into owned memory, then the database
 * is closed.
 */
static int	nmap_service_cache_load(void)
{
	struct servent	*service;

	if (g_service_cache_loaded)
		return (1);
	if (!nmap_service_cache_load_nmap())
	{
		nmap_service_cache_cleanup();
		setservent(1);
		service = getservent();
		while (service)
		{
			if (!nmap_service_cache_add(service))
			{
				endservent();
				nmap_service_cache_cleanup();
				return (0);
			}
			service = getservent();
		}
		endservent();
	}
	g_service_cache_loaded = 1;
	if (atexit(nmap_service_cache_cleanup) != 0)
	{
		nmap_service_cache_cleanup();
		return (0);
	}
	return (1);
}

/**
 * @brief Cached equivalent of getservbyport() for report generation.
 *
 * @param port Port in network byte order, matching getservbyport().
 * @param proto "tcp" or "udp".
 *
 * @return Pointer to temporary servent-compatible data, or NULL.
 *
 * @note The returned object behaves like libc's getservbyport() result:
 *       subsequent calls may overwrite it. Output generation is single
 *       threaded, so this is sufficient and keeps the existing service.c API.
 */
static struct servent	*nmap_cached_getservbyport(int port,
		const char *proto)
{
	static struct servent	result;
	static char				*aliases[] = {NULL};
	size_t					index;
	t_nmap_service_cache_entry	*entry;

	if (!proto || !nmap_service_cache_load())
		return (NULL);
	if (strcmp(proto, "tcp") != 0 && strcmp(proto, "udp") != 0)
		return (NULL);
	index = g_service_index[strcmp(proto, "tcp") != 0]
		[ntohs((uint16_t)port)];
	if (!index)
		return (NULL);
	entry = &g_service_cache[index - 1];
	result.s_name = entry->name;
	result.s_aliases = aliases;
	result.s_port = entry->port;
	result.s_proto = entry->proto;
	return (&result);
}

/** Return whether at least one TCP scan exists for this port. */
static int	has_tcp_scan(const t_nmap_port_view *view)
{
	return (view->syn || view->null_scan || view->fin
		|| view->xmas || view->ack);
}

/**
 * @brief Lookup one conventional service name from the cached port table.
 *
 * nmap_cached_getservbyport() performs no network service detection. It is only the
 * conventional (port, protocol) -> service-name mapping.
 */
static int	lookup_service(uint16_t port, const char *protocol,
		char *dst, size_t dst_size)
{
	struct servent	*service;

	service = nmap_cached_getservbyport(htons(port), protocol);
	if (!service || !service->s_name)
		return (0);
	snprintf(dst, dst_size, "%s", service->s_name);
	return (1);
}

/**
 * @brief Produce the SERVICE column for one port.
 *
 * TCP and UDP are looked up independently because the same numeric port can
 * theoretically have different conventional service names per protocol.
 */
void	nmap_output_service_name(const t_nmap_port_view *view,
		char *dst, size_t dst_size)
{
	char	tcp[NMAP_OUTPUT_SERVICE_MAX];
	char	udp[NMAP_OUTPUT_SERVICE_MAX];
	int		have_tcp;
	int		have_udp;

	if (!view || !dst || dst_size == 0)
		return ;
	tcp[0] = '\0';
	udp[0] = '\0';
	have_tcp = 0;
	have_udp = 0;
	if (has_tcp_scan(view))
		have_tcp = lookup_service(view->port, "tcp",
				tcp, sizeof(tcp));
	if (view->udp)
		have_udp = lookup_service(view->port, "udp",
				udp, sizeof(udp));
	if (have_tcp && have_udp && strcmp(tcp, udp) == 0)
		snprintf(dst, dst_size, "%s", tcp);
	else if (have_tcp && have_udp)
		snprintf(dst, dst_size, "%s|%s", tcp, udp);
	else if (have_tcp)
		snprintf(dst, dst_size, "%s", tcp);
	else if (have_udp)
		snprintf(dst, dst_size, "%s", udp);
	else
	{
		snprintf(dst, dst_size, "unknown");
	}
}
