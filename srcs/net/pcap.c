#include "config.h"

#include <pcap/pcap.h>
#include <stdio.h>
#include <string.h>

#define NMAP_PCAP_SNAPLEN 65535
#define NMAP_PCAP_TIMEOUT_MS 1
#define NMAP_PCAP_FILTER_SIZE 1024

/**
 * @brief Build the target-family BPF capture filter.
 *
 * @note Direct replies are restricted to target -> local traffic. ICMP errors
 *       may come from intermediate routers, so the error branch only requires
 *       the packet to be addressed to the local source address.
 */
static int	build_pcap_filter(const t_nmap_config *config,
		char *filter, size_t filter_size)
{
	int	ret;

	if (config->target.addr.family == AF_INET)
	{
		ret = snprintf(filter, filter_size,
				"((ip and src host %s and dst host %s)"
				" or (icmp and dst host %s))",
				config->target.ip, config->route.src_ip,
				config->route.src_ip);
	}
	else if (config->target.addr.family == AF_INET6)
	{
		ret = snprintf(filter, filter_size,
				"((ip6 and src host %s and dst host %s)"
				" or (icmp6 and dst host %s))",
				config->target.ip, config->route.src_ip,
				config->route.src_ip);
	}
	else
		return (0);
	return (ret >= 0 && (size_t)ret < filter_size);
}

/**
 * @brief Apply capture settings before activation.
 */
static int	apply_pcap_settings(pcap_t *handle)
{
	if (pcap_set_snaplen(handle, NMAP_PCAP_SNAPLEN) < 0)
		return (0);
	if (pcap_set_promisc(handle, 0) < 0)
		return (0);
	if (pcap_set_timeout(handle, NMAP_PCAP_TIMEOUT_MS) < 0)
		return (0);
	return (1);
}

/**
 * @brief Create and activate the pcap handle on the selected route interface.
 */
static int	open_pcap_handle(t_nmap_config *config)
{
	pcap_t	*handle;

	memset(config->capture.errbuf, 0, sizeof(config->capture.errbuf));
	handle = pcap_create(config->route.iface, config->capture.errbuf);
	if (!handle)
	{
		fprintf(stderr, "ft_nmap: pcap_create: %s\n",
			config->capture.errbuf);
		return (0);
	}
	if (!apply_pcap_settings(handle))
	{
		fprintf(stderr, "ft_nmap: pcap settings: %s\n", pcap_geterr(handle));
		pcap_close(handle);
		return (0);
	}
	if (pcap_activate(handle) < 0)
	{
		fprintf(stderr, "ft_nmap: pcap_activate: %s\n", pcap_geterr(handle));
		pcap_close(handle);
		return (0);
	}
	config->capture.handle = handle;
	return (1);
}

/**
 * @brief Compile and install the capture filter.
 */
static int	install_pcap_filter(t_nmap_config *config)
{
	struct bpf_program	program;
	char				filter[NMAP_PCAP_FILTER_SIZE];

	if (!build_pcap_filter(config, filter, sizeof(filter)))
	{
		fprintf(stderr, "ft_nmap: pcap filter too long\n");
		return (0);
	}
	if (pcap_compile(config->capture.handle, &program,
			filter, 1, PCAP_NETMASK_UNKNOWN) < 0)
	{
		fprintf(stderr, "ft_nmap: pcap_compile: %s\n",
			pcap_geterr(config->capture.handle));
		return (0);
	}
	if (pcap_setfilter(config->capture.handle, &program) < 0)
	{
		fprintf(stderr, "ft_nmap: pcap_setfilter: %s\n",
			pcap_geterr(config->capture.handle));
		pcap_freecode(&program);
		return (0);
	}
	pcap_freecode(&program);
	return (1);
}

/**
 * @brief Expose pcap as a non-blocking selectable fd for the event loop.
 */
static int	prepare_pcap_fd(t_nmap_config *config)
{
	config->capture.fd = pcap_get_selectable_fd(config->capture.handle);
	if (config->capture.fd < 0)
	{
		fprintf(stderr, "ft_nmap: pcap fd is not selectable\n");
		return (0);
	}
	if (pcap_setnonblock(config->capture.handle, 1,
			config->capture.errbuf) < 0)
	{
		fprintf(stderr, "ft_nmap: pcap_setnonblock: %s\n",
			config->capture.errbuf);
		return (0);
	}
	config->capture.datalink = pcap_datalink(config->capture.handle);
	return (1);
}

/**
 * @brief Prepare packet capture before the first probe is scheduled.
 */
int	nmap_prepare_pcap(t_nmap_config *config, int *exit_status)
{
	if (!config)
	{
		if (exit_status)
			*exit_status = 1;
		return (0);
	}
	memset(&config->capture, 0, sizeof(config->capture));
	config->capture.fd = -1;
	config->capture.datalink = -1;
	if (!open_pcap_handle(config)
		|| !install_pcap_filter(config)
		|| !prepare_pcap_fd(config))
	{
		if (config->capture.handle)
			pcap_close(config->capture.handle);
		config->capture.handle = NULL;
		config->capture.fd = -1;
		config->capture.datalink = -1;
		if (exit_status)
			*exit_status = 1;
		return (0);
	}
	return (1);
}
