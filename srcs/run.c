#include "ft_nmap.h"
#include "engine/engine_internal.h"
#include "runtime/runtime_internal.h"
#include "output/output.h"

#include <stdio.h>

int nmap_run(t_nmap_config *config, int *exit_status)
{
    t_nmap_engine engine;
    uint64_t duration;
    int worked;
    int status;
    size_t total;
    size_t done;
    size_t failed;

    if (!config)
        goto fail;
    status = 0;
    if (!nmap_engine_prepare(&engine, config))
    {
        fprintf(stderr, "ft_nmap: cannot prepare global engine\n");
        nmap_cleanup_engine(&engine);
        goto fail;
    }
    /* The banner describes the entire prepared routing plan, not each target. */
    nmap_output_print_scan_banner(&engine);
    engine.started_ms = nmap_now_ms();
    if (!nmap_prepare_sender_pool(&engine, &status))
        worked = 0;
    else
        worked = nmap_engine_run_loop(&engine, &status);
    /* No report should be printed while any sender still owns a probe. */
    nmap_stop_sender_pool(&engine);
    duration = nmap_now_ms() - engine.started_ms;
    total = engine.effective_targets;
    done = engine.completed_count;
    failed = engine.failed_count;
    /* All workers have stopped: report immutable results in input-file order. */
    if (done)
        puts("\n================ RESULTS ================\n");
    for (size_t i = 0; i < engine.target_count; ++i)
        if (engine.targets[i].status == NMAP_TARGET_FINISHED)
            nmap_output_print_target_report(&engine.targets[i]);
    if (done)
        nmap_output_print_results_legend();
    nmap_output_print_run_summary(total, done, duration);
    nmap_cleanup_engine(&engine);
    if (!worked || failed > 0)
    {
        if (exit_status)
            *exit_status = status ? status : 1;
        return (0);
    }
    return (1);
fail:
    if (exit_status)
        *exit_status = 1;
    return (0);
}
