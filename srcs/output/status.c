#include "output/output_internal.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

/** A fixed scan banner is emitted once, after ALL routes and captures exist. */
static void print_ports(const t_nmap_scan *scan)
{
    size_t i;
    int contiguous;

    contiguous = (scan->port_count > 0);
    for (i = 1; i < scan->port_count; ++i)
        if (scan->ports[i] != (uint16_t)(scan->ports[i - 1] + 1))
            contiguous = 0;
    printf("Ports      : ");
    if (contiguous && scan->port_count > 1)
        printf("%u-%u (%zu)\n", scan->ports[0],
            scan->ports[scan->port_count - 1], scan->port_count);
    else if (scan->port_count <= 12)
    {
        for (i = 0; i < scan->port_count; ++i)
            printf("%s%u", i ? "," : "", scan->ports[i]);
        printf(" (%zu)\n", scan->port_count);
    }
    else
        printf("%zu selected ports\n", scan->port_count);
}

static void print_scan_name(uint32_t mask, uint32_t flag,
        const char *name, int *first)
{
    if (!(mask & flag))
        return ;
    printf("%s%s", *first ? "" : ",", name);
    *first = 0;
}

static void print_scans(uint32_t mask)
{
    int first;

    first = 1;
    printf("Scans      : ");
    print_scan_name(mask, NMAP_SCAN_SYN, "SYN", &first);
    print_scan_name(mask, NMAP_SCAN_NULL, "NULL", &first);
    print_scan_name(mask, NMAP_SCAN_FIN, "FIN", &first);
    print_scan_name(mask, NMAP_SCAN_XMAS, "XMAS", &first);
    print_scan_name(mask, NMAP_SCAN_ACK, "ACK", &first);
    print_scan_name(mask, NMAP_SCAN_UDP, "UDP", &first);
    putchar('\n');
}

static void print_timing(const t_nmap_scan *scan)
{
    const uint32_t tcp = NMAP_SCAN_SYN | NMAP_SCAN_NULL
        | NMAP_SCAN_FIN | NMAP_SCAN_XMAS | NMAP_SCAN_ACK;

    printf("Retries    : %d\n", scan->retries);
    if ((scan->scan_mask & tcp) && (scan->scan_mask & NMAP_SCAN_UDP))
        printf("Timeouts   : TCP %dms / UDP %dms\n",
            scan->tcp_timeout_ms, scan->udp_timeout_ms);
    else if (scan->scan_mask & NMAP_SCAN_UDP)
        printf("Timeout    : UDP %dms\n", scan->udp_timeout_ms);
    else
        printf("Timeout    : TCP %dms\n", scan->tcp_timeout_ms);
    printf("TTL / Hop  : %d\n", scan->ttl);
    if (scan->thread_count == 0)
    {
        printf("Mode       : adaptive (multi-target / multi-interface)\n");
        printf("Window     : %d per interface, target-local UDP pacing\n",
            scan->window_size);
    }
    else
    {
        printf("Mode       : naive (%d workers, global cap %d)\n",
            scan->thread_count, scan->thread_count);
        printf("Policy     : fixed timeouts/retries; no pacing or congestion window\n");
    }
}

/** Count interfaces with at least one runnable destination. */
static size_t count_used_interfaces(const t_nmap_engine *engine)
{
    size_t i;
    size_t j;
    size_t count;

    count = 0;
    for (i = 0; i < engine->iface_count; ++i)
        for (j = 0; j < engine->target_count; ++j)
            if (engine->targets[j].iface == &engine->ifaces[i]
                && engine->targets[j].status == NMAP_TARGET_PREPARED)
            {
                count++;
                break ;
            }
    return (count);
}

static void print_interface_targets(const t_nmap_engine *engine, size_t index)
{
    const t_nmap_iface_ctx *iface;
    const t_nmap_target_ctx *ctx;
    size_t i;

    iface = &engine->ifaces[index];
    printf("\n  %s (ifindex %u)\n", iface->iface, iface->ifindex);
    for (i = 0; i < engine->target_count; ++i)
    {
        ctx = &engine->targets[i];
        if (ctx->status != NMAP_TARGET_PREPARED || ctx->iface != iface)
            continue ;
        printf("    %-5s %-39s  source %s",
            ctx->target.addr.family == AF_INET6 ? "IPv6" : "IPv4",
            ctx->target.ip, ctx->route.src_ip);
        if (ctx->target.hostname[0] != '\0')
            printf("  (%s)", ctx->target.hostname);
        putchar('\n');
    }
}

void nmap_output_print_scan_banner(const t_nmap_engine *engine)
{
    const t_nmap_scan *scan;
    size_t i;
    size_t skipped;

    if (!engine || !engine->config)
        return ;
    scan = &engine->config->scan;
    skipped = engine->target_count - engine->effective_targets;
    puts("\n================ ft_nmap ================");
    printf("Targets    : %zu ready / %zu unique",
        engine->effective_targets - engine->failed_count,
        engine->effective_targets);
    if (engine->failed_count || skipped)
        printf(" (%zu failed preparation, %zu duplicate(s) skipped)",
            engine->failed_count, skipped);
    putchar('\n');
    printf("Interfaces : %zu\n", count_used_interfaces(engine));
    print_ports(scan);
    print_scans(scan->scan_mask);
    print_timing(scan);
    puts("\nDestinations grouped by outgoing interface:");
    for (i = 0; i < engine->iface_count; ++i)
    {
        size_t j;

        for (j = 0; j < engine->target_count; ++j)
            if (engine->targets[j].iface == &engine->ifaces[i]
                && engine->targets[j].status == NMAP_TARGET_PREPARED)
                break ;
        if (j < engine->target_count)
            print_interface_targets(engine, i);
    }
    if (engine->failed_count)
    {
        puts("\nPreparation failures:");
        for (i = 0; i < engine->target_count; ++i)
            if (engine->targets[i].status == NMAP_TARGET_FAILED)
                printf("    %s\n", engine->config->targets.items[i]);
    }
    puts("\n-----------------------------------------");
    if (isatty(STDIN_FILENO))
        puts("Scanning... Press Enter for progress by target.\n");
    else
        puts("Scanning...\n");
    fflush(stdout);
}

static const char *status_name(t_nmap_target_status status)
{
    if (status == NMAP_TARGET_PREPARED)
        return ("WAITING");
    if (status == NMAP_TARGET_ACTIVE)
        return ("ACTIVE");
    if (status == NMAP_TARGET_FINISHED)
        return ("DONE");
    if (status == NMAP_TARGET_FAILED)
        return ("FAILED");
    return ("SKIPPED");
}

/** No runtime locks here: the event loop passes immutable snapshots. */
void nmap_output_print_target_progress(const t_nmap_progress *global,
        const t_nmap_target_progress *targets, size_t target_count,
        const t_nmap_iface_ctx *ifaces, size_t iface_count,
        size_t completed_targets, size_t expected_targets)
{
    size_t i;
    size_t j;
    double pct;

    if (!global || !targets)
        return ;
    pct = global->total ? 100.0 * (double)global->done
        / (double)global->total : 100.0;
    printf("\n========== PROGRESS (global: %llums) ==========\n",
        (unsigned long long)global->elapsed_ms);
    printf("Targets : %zu/%zu complete | Probes: %zu/%zu (%.1f%%) | "
        "queued %zu | inflight %zu | benched %zu\n",
        completed_targets, expected_targets, global->done, global->total,
        pct, global->queued, global->outstanding, global->benched);
    for (i = 0; i < iface_count; ++i)
    {
        int printed;

        printed = 0;
        for (j = 0; j < target_count; ++j)
        {
            if (targets[j].ifindex != ifaces[i].ifindex
                || targets[j].status == NMAP_TARGET_DUPLICATE)
                continue ;
            if (!printed++)
                printf("\n  %s\n", ifaces[i].iface);
            pct = targets[j].total ? 100.0 * (double)targets[j].done
                / (double)targets[j].total : 0.0;
            printf("    %-39s %-8s %5zu/%-5zu %5.1f%%"
                "  queued %-4zu inflight %-4zu benched %-4zu\n",
                targets[j].name, status_name(targets[j].status),
                targets[j].done, targets[j].total, pct, targets[j].queued,
                targets[j].outstanding, targets[j].benched);
        }
    }
    for (j = 0; j < target_count; ++j)
        if (targets[j].status == NMAP_TARGET_FAILED && !targets[j].ifindex)
            printf("  %-39s FAILED (preparation)\n", targets[j].name);
    puts("=============================================\n");
    fflush(stdout);
}
