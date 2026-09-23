
#include "config.h"

#include <pcap/pcap.h>
#include <stdio.h>
#include <string.h>

#define NMAP_PCAP_SNAPLEN 65535
#define NMAP_PCAP_TIMEOUT_MS 1

/**
 * A capture is shared across all IPv4/IPv6 targets routed through this
 * interface. Restrict to IP at the kernel; exact address/probe validation is
 * deliberately performed in userspace, including ICMP from intermediate hops.
 * Do NOT filter ICMP by the outer sender (which may not be our target).
 */
int nmap_prepare_pcap(t_nmap_iface_ctx *iface, int *exit_status)
{
    struct bpf_program program;
    pcap_t *handle;
    int compiled;

    if (!iface)
        goto fail;
    if (iface->capture.handle)
        return (1);
    memset(&iface->capture, 0, sizeof(iface->capture));
    iface->capture.fd = -1;
    iface->capture.datalink = -1;
    handle = pcap_create(iface->iface, iface->capture.errbuf);
    if (!handle)
        goto fail_print;
    if (pcap_set_snaplen(handle, NMAP_PCAP_SNAPLEN) < 0
        || pcap_set_promisc(handle, 0) < 0
        || pcap_set_timeout(handle, NMAP_PCAP_TIMEOUT_MS) < 0
        || pcap_activate(handle) < 0)
        goto fail_handle;
    compiled = pcap_compile(handle, &program, "ip or ip6", 1,
            PCAP_NETMASK_UNKNOWN);
    if (compiled < 0)
        goto fail_handle;
    if (pcap_setfilter(handle, &program) < 0)
    {
        pcap_freecode(&program);
        goto fail_handle;
    }
    pcap_freecode(&program);
    iface->capture.fd = pcap_get_selectable_fd(handle);
    if (iface->capture.fd < 0
        || pcap_setnonblock(handle, 1, iface->capture.errbuf) < 0)
        goto fail_handle;
    iface->capture.datalink = pcap_datalink(handle);
    iface->capture.handle = handle;
    return (1);
fail_handle:
    fprintf(stderr, "ft_nmap: pcap %s: %s\n", iface->iface,
        pcap_geterr(handle));
    pcap_close(handle);
    goto fail;
fail_print:
    fprintf(stderr, "ft_nmap: pcap %s: %s\n", iface->iface,
        iface->capture.errbuf);
fail:
    if (exit_status)
        *exit_status = 1;
    return (0);
}
