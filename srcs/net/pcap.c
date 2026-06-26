#include "config.h"

#include <stdio.h>
#include <string.h>
#include <pcap/pcap.h>

#define NMAP_PCAP_SNAPLEN 65535
#define NMAP_PCAP_TIMEOUT_MS 1
#define NMAP_PCAP_FILTER_SIZE 256

/**
 * @brief Build the BPF filter used by pcap.
 *
 * @param config Global nmap configuration.
 * @param filter Destination buffer receiving the filter string.
 * @param filter_size Size of the destination buffer.
 *
 * @return 1 on success, 0 if the filter does not fit.
 *
 * @note The filter accepts TCP, UDP and ICMP replies. TCP covers SYN, NULL,
 *       FIN, XMAS and ACK scans. UDP covers direct UDP replies. ICMP covers
 *       UDP unreachable replies and other network-level errors.
 */
static int	build_pcap_filter(t_nmap_config *config,
		char *filter, size_t filter_size)
{
	int	ret;

	ret = snprintf(filter, filter_size,
			"(((tcp or udp) and src host %s and dst host %s)"
			" or (icmp and dst host %s))",
			config->target.ip,
			config->route.src_ip,
			config->route.src_ip);
	if (ret < 0 || (size_t)ret >= filter_size)
		return (0);
	return (1);
}

/**
 * @brief Apply pcap options before activating the handle.
 *
 * @param handle Pcap handle created with pcap_create().
 *
 * @return 1 on success, 0 on pcap option failure.
 *
 * @note The timeout is kept very short so pcap does not buffer packets for
 *       too long before the runtime loop drains available replies.
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
 * @brief Create and activate the pcap handle.
 *
 * @param config Global nmap configuration.
 *
 * @return 1 on success, 0 on pcap creation, setup or activation failure.
 *
 * @note This only prepares the capture path. No probe should be sent before
 *       this function and the filter setup have succeeded.
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
		fprintf(stderr, "ft_nmap: pcap settings failed: %s\n",
			pcap_geterr(handle));
		pcap_close(handle);
		return (0);
	}
	if (pcap_activate(handle) < 0)
	{
		fprintf(stderr, "ft_nmap: pcap_activate: %s\n",
			pcap_geterr(handle));
		pcap_close(handle);
		return (0);
	}
	config->capture.handle = handle;
	return (1);
}

/**
 * @brief Compile and install the BPF filter.
 *
 * @param config Global nmap configuration.
 *
 * @return 1 on success, 0 on filter build, compile or install failure.
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
 * @brief Prepare pcap for the runtime event loop.
 *
 * @param config Global nmap configuration.
 *
 * @return 1 on success, 0 if pcap cannot provide a selectable fd or cannot be
 *         switched to non-blocking mode.
 *
 * @note The selectable fd is used by select(); non-blocking mode lets the
 *       receive step drain all currently available packets without blocking.
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
 * @brief Prepare packet capture before the first probe is sent.
 *
 * @param config Global nmap configuration.
 * @param exit_status Output exit status set on fatal setup error.
 *
 * @return 1 on success, 0 on pcap setup failure.
 *
 * @note This function owns the complete pcap setup sequence: create, configure,
 *       activate, filter, selectable fd. On failure, any opened handle is closed.
 */
int	nmap_prepare_pcap(t_nmap_config *config, int *exit_status)
{
	if (!config)
	{
		if (exit_status)
			*exit_status = 1;
		return (0);
	}
	config->capture.handle = NULL;
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