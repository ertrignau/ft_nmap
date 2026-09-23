#include "ft_nmap.h"
#include "debug/debug.h"
#include "runtime/runtime_internal.h"

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

static uint64_t now_us(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return (0);
    return ((uint64_t)ts.tv_sec * 1000000ULL
        + (uint64_t)ts.tv_nsec / 1000ULL);
}

static void minimum(uint64_t *current, uint64_t candidate)
{
    if (candidate < *current)
        *current = candidate;
}

/** Read every active runtime's nearest real deadline; no global target lock. */
static int next_wait_ms(t_nmap_engine *engine)
{
    const t_nmap_runtime *rt;
    t_nmap_target_ctx *ctx;
    uint64_t now;
    uint64_t wait;
    uint64_t deadline;
    uint64_t elapsed;
    size_t i;
    size_t j;
    int pending_udp;

    now = nmap_now_ms();
    wait = 100; /* Bound signal/reclamation latency even without a packet. */
    for (i = 0; i < engine->target_count; ++i)
    {
        ctx = &engine->targets[i];
        if (ctx->status != NMAP_TARGET_ACTIVE)
            continue ;
        rt = &ctx->runtime;
        pthread_mutex_lock(&ctx->runtime.lock);
        if (rt->queued_count > 0 || atomic_load(&ctx->live_jobs) > 0)
            minimum(&wait, 1);
        pending_udp = 0;
        for (j = 0; j < rt->probe_count; ++j)
        {
            if (rt->probes[j].state == PROBE_PENDING
                && nmap_probe_is_udp(&rt->probes[j]))
                pending_udp = 1;
            if (rt->probes[j].state != PROBE_OUTSTANDING)
                continue ;
            deadline = rt->probes[j].deadline_ms;
            minimum(&wait, (now < deadline) ? deadline - now : 0);
        }
        if (ctx->scan->thread_count == 0 && pending_udp
            && rt->last_udp_sent_ms > 0 && rt->timing.udp_send_gap_ms > 0)
        {
            elapsed = (now >= rt->last_udp_sent_ms)
                ? now - rt->last_udp_sent_ms : 0;
            if (elapsed < rt->timing.udp_send_gap_ms)
                minimum(&wait, rt->timing.udp_send_gap_ms - elapsed);
        }
        pthread_mutex_unlock(&ctx->runtime.lock);
    }
    return ((int)wait);
}

int nmap_runtime_wait(t_nmap_engine *engine, int *exit_status)
{
    static int stdin_available = 1;
    struct pollfd fds[NMAP_MAX_TARGETS + 1];
    nfds_t count;
    size_t i;
    int timeout;
    int ret;
    uint64_t before;
    uint64_t after;
    int stdin_index;

    if (!engine)
        goto fail;
    count = 0;
    for (i = 0; i < engine->iface_count; ++i)
    {
        if (engine->ifaces[i].active_targets == 0)
            continue ;
        if (engine->ifaces[i].capture.fd < 0)
            goto fail;
        fds[count++] = (struct pollfd){engine->ifaces[i].capture.fd, POLLIN, 0};
    }
    stdin_index = -1;
    if (stdin_available && isatty(STDIN_FILENO))
    {
        stdin_index = (int)count;
        fds[count++] = (struct pollfd){STDIN_FILENO, POLLIN, 0};
    }
    timeout = next_wait_ms(engine);
    before = now_us();
    ret = poll(fds, count, timeout);
    after = now_us();
    PROF_ADD_VALUE(NMAP_PROF_SELECT_REQUESTED, (uint64_t)timeout * 1000ULL);
    PROF_ADD_VALUE(NMAP_PROF_SELECT_WAIT, after - before);
    if (ret < 0)
    {
        if (errno == EINTR)
            return (NMAP_WAIT_READY);
        perror("ft_nmap: poll");
        goto fail;
    }
    for (i = 0; i < count; ++i)
        if (fds[i].revents & (POLLNVAL | POLLERR))
            goto fail;
    if (stdin_index >= 0 && (fds[stdin_index].revents & POLLIN))
    {
        char buf[64];
        if (read(STDIN_FILENO, buf, sizeof(buf)) > 0)
            return (NMAP_WAIT_PROGRESS);
        stdin_available = 0;
    }
    return (NMAP_WAIT_READY);
fail:
    if (exit_status)
        *exit_status = 1;
    return (NMAP_WAIT_ERROR);
}
