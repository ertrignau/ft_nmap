#include "ft_nmap.h"
#include "debug/debug.h"
#include "net/address.h"
#include "packet/packet.h"
#include "runtime/runtime_internal.h"

#include <pcap/pcap.h>
#include <stdio.h>

static uint8_t guess_initial_hop_limit(uint8_t observed)
{
    if (observed <= 64)
        return (64);
    if (observed <= 128)
        return (128);
    return (255);
}

static void note_os_observation(t_nmap_target_ctx *ctx,
        const t_nmap_reply *reply)
{
    if (!ctx->scan->os_detection || reply->hop_limit == 0
        || !nmap_ip_equal(&reply->src_addr, &ctx->target.addr))
        return ;
    if (ctx->target.observed_hop_limit != 0
        && reply->hop_limit <= ctx->target.observed_hop_limit)
        return ;
    ctx->target.observed_hop_limit = reply->hop_limit;
    ctx->target.initial_hop_limit = guess_initial_hop_limit(reply->hop_limit);
}

static t_scan_reason reply_reason(const t_nmap_reply *reply)
{
    t_scan_reason reason = {0};

    if (reply->type == NMAP_REPLY_UDP)
        reason.kind = SCAN_REASON_UDP_REPLY;
    else if (reply->type == NMAP_REPLY_TCP)
    {
        reason.kind = SCAN_REASON_TCP;
        reason.tcp_flags = reply->tcp_flags;
    }
    else if (reply->type == NMAP_REPLY_ICMP4
        || reply->type == NMAP_REPLY_ICMP6)
    {
        reason.kind = SCAN_REASON_ICMP;
        reason.family = (reply->type == NMAP_REPLY_ICMP4)
            ? AF_INET : AF_INET6;
        reason.icmp_type = reply->icmp_type;
        reason.icmp_code = reply->icmp_code;
    }
    return (reason);
}

/** Choose the target from the packet, NOT from the outer ICMP source. */
static t_nmap_target_ctx *find_reply_target(t_nmap_engine *engine,
        t_nmap_iface_ctx *iface, t_nmap_reply *reply, t_probe **matched)
{
    const t_nmap_ip_addr *destination;
    const t_nmap_ip_addr *local;
    size_t i;
    t_nmap_target_ctx *ctx;

    if (reply->type == NMAP_REPLY_TCP || reply->type == NMAP_REPLY_UDP)
    {
        destination = &reply->src_addr;
        local = &reply->dst_addr;
    }
    else if (reply->type == NMAP_REPLY_ICMP4
        || reply->type == NMAP_REPLY_ICMP6)
    {
        destination = &reply->original_dst_addr;
        local = &reply->original_src_addr;
    }
    else
        return (NULL);
    for (i = 0; i < engine->target_count; ++i)
    {
        ctx = &engine->targets[i];
        if (ctx->status != NMAP_TARGET_ACTIVE || ctx->iface != iface
            || !nmap_ip_equal(destination, &ctx->target.addr)
            || !nmap_ip_equal(local, &ctx->route.src_addr))
            continue ;
        *matched = nmap_find_matching_probe(ctx, reply);
        if (*matched)
            return (ctx);
    }
    return (NULL);
}

static void handle_packet(t_nmap_engine *engine, t_nmap_iface_ctx *iface,
        const unsigned char *packet, size_t length)
{
    t_nmap_reply reply;
    t_nmap_target_ctx *ctx;
    t_probe *probe;
    t_scan_result result;
    uint64_t started;

    DEBUG_RECV_PACKET(packet, length);
    started = PROF_START();
    if (!nmap_parse_pcap_packet(iface, packet, length, &reply))
    {
        PROF_ADD(NMAP_PROF_PACKET_PARSE_TOTAL, started);
        PROF_COUNT(NMAP_PROF_PACKET_IGNORED);
        return ;
    }
    PROF_ADD(NMAP_PROF_PACKET_PARSE_TOTAL, started);
    PROF_COUNT(NMAP_PROF_PACKET_PARSED);
    probe = NULL;
    started = PROF_START();
    ctx = find_reply_target(engine, iface, &reply, &probe);
    PROF_ADD(NMAP_PROF_MATCH_PROBE, started);
    if (!ctx)
    {
        PROF_COUNT(NMAP_PROF_PACKET_IGNORED);
        return ;
    }
    started = PROF_START();
    result = nmap_classify_reply(ctx, probe, &reply);
    PROF_ADD(NMAP_PROF_CLASSIFY, started);
    if (result == SCAN_RESULT_UNKNOWN)
    {
        PROF_COUNT(NMAP_PROF_PACKET_IGNORED);
        return ;
    }
    note_os_observation(ctx, &reply);
    PROF_COUNT(NMAP_PROF_PACKET_MATCHED);
    nmap_mark_probe_done(ctx, probe, result, reply_reason(&reply), "reply");
}

/** Bounded drain: one saturated interface must not starve other interfaces. */
int nmap_runtime_drain_replies(t_nmap_engine *engine,
        t_nmap_iface_ctx *iface, int *exit_status)
{
    struct pcap_pkthdr *header;
    const unsigned char *packet;
    int ret;
    int i;
    uint64_t started;

    if (!iface || !iface->capture.handle)
        goto fail;
    for (i = 0; i < 512; ++i)
    {
        started = PROF_START();
        ret = pcap_next_ex(iface->capture.handle, &header, &packet);
        PROF_ADD(NMAP_PROF_PCAP_NEXT_EX, started);
        if (ret == 1)
        {
            PROF_COUNT(NMAP_PROF_PACKET_SEEN);
            handle_packet(engine, iface, packet, header->caplen);
        }
        else if (ret == 0 || ret == PCAP_ERROR_BREAK)
            return (1);
        else
        {
            fprintf(stderr, "ft_nmap: pcap_next_ex on %s: %s\n",
                iface->iface, pcap_geterr(iface->capture.handle));
            goto fail;
        }
    }
    return (1);
fail:
    if (exit_status)
        *exit_status = 1;
    return (0);
}
