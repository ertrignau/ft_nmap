#include "config.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef IPV6_HDRINCL
# define IPV6_HDRINCL 36
#endif

/** One reusable raw socket per (interface, address family). */
int nmap_prepare_send_socket(t_nmap_iface_ctx *iface,
        sa_family_t family, int *exit_status)
{
    t_nmap_socket *sock;
    int fd;
    int on;
    int saved;

    if (!iface || (family != AF_INET && family != AF_INET6))
        goto fail;
    sock = (family == AF_INET) ? &iface->socket4 : &iface->socket6;
    if (sock->send_fd >= 0)
        return (1);
    fd = socket(family, SOCK_RAW, IPPROTO_RAW);
    if (fd < 0)
        goto system_fail;
    on = 1;
    if (setsockopt(fd, family == AF_INET ? IPPROTO_IP : IPPROTO_IPV6,
            family == AF_INET ? IP_HDRINCL : IPV6_HDRINCL,
            &on, sizeof(on)) < 0
        || setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
            iface->iface, strlen(iface->iface) + 1) < 0)
    {
        saved = errno;
        close(fd);
        errno = saved;
        goto system_fail;
    }
    sock->send_fd = fd;
    sock->family = family;
    return (1);
system_fail:
    fprintf(stderr, "ft_nmap: raw socket on %s: %s\n",
        iface->iface, strerror(errno));
fail:
    if (exit_status)
        *exit_status = 1;
    return (0);
}
