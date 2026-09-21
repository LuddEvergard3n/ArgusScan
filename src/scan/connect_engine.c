#include "scan/connect_engine.h"

#include "engine/thread_pool.h"

#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <time.h>

typedef struct {
    struct in_addr address;
    uint16_t port;
    int timeout_ms;
    ArgusConnectResult *result;
} ConnectJob;

static void connect_worker(void *context)
{
    ConnectJob *job = context;

    if (!argus_tcp_connect_ipv4(job->address, job->port, job->timeout_ms, job->result)) {
        job->result->port = job->port;
        job->result->state = ARGUS_PORT_FILTERED;
    }
}

static void scan_delay(int milliseconds)
{
    struct timespec remaining;
    struct timespec requested;

    if (milliseconds <= 0) {
        return;
    }

    requested.tv_sec = milliseconds / 1000;
    requested.tv_nsec = (long)(milliseconds % 1000) * 1000000L;
    while (nanosleep(&requested, &remaining) != 0 && errno == EINTR) {
        requested = remaining;
    }
}

bool argus_tcp_connect_scan(
    const ArgusIPv4Target *target,
    const ArgusPortList *ports,
    const ArgusTimingConfig *timing,
    ArgusConnectResult *results
)
{
    ArgusThreadPool *pool;
    ConnectJob *jobs;
    size_t thread_count;
    size_t queue_capacity;
    size_t index;
    bool submitted = true;

    if (target == NULL || ports == NULL || ports->ports == NULL || ports->count == 0U ||
        timing == NULL || results == NULL || timing->max_parallelism <= 0 ||
        timing->max_outstanding_probes <= 0 || timing->initial_rtt_timeout_ms <= 0) {
        return false;
    }

    thread_count = (size_t)timing->max_parallelism;
    if (thread_count > ports->count) {
        thread_count = ports->count;
    }
    queue_capacity = (size_t)timing->max_outstanding_probes;
    if (queue_capacity > ports->count) {
        queue_capacity = ports->count;
    }

    jobs = calloc(ports->count, sizeof(*jobs));
    if (jobs == NULL) {
        return false;
    }

    pool = argus_thread_pool_create(thread_count, queue_capacity);
    if (pool == NULL) {
        free(jobs);
        return false;
    }

    for (index = 0U; index < ports->count; ++index) {
        jobs[index].address = target->address;
        jobs[index].port = ports->ports[index];
        jobs[index].timeout_ms = timing->initial_rtt_timeout_ms;
        jobs[index].result = &results[index];
        if (!argus_thread_pool_submit(pool, connect_worker, &jobs[index])) {
            submitted = false;
            break;
        }
        if (index + 1U < ports->count) {
            scan_delay(timing->scan_delay_ms);
        }
    }

    argus_thread_pool_wait(pool);
    argus_thread_pool_destroy(pool);
    free(jobs);
    return submitted;
}

