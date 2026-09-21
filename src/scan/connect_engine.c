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
    int64_t host_deadline_ms;
    ArgusConnectResult *result;
} ConnectJob;

static int64_t monotonic_ms(void)
{
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return -1;
    }
    return (int64_t)now.tv_sec * 1000 + (int64_t)now.tv_nsec / 1000000;
}

static void connect_worker(void *context)
{
    ConnectJob *job = context;
    int timeout_ms = job->timeout_ms;

    if (job->host_deadline_ms > 0) {
        int64_t now_ms = monotonic_ms();
        int64_t remaining_ms;

        if (now_ms < 0 || (remaining_ms = job->host_deadline_ms - now_ms) <= 0) {
            job->result->port = job->port;
            job->result->state = ARGUS_PORT_FILTERED;
            job->result->latency_ms = 0;
            job->result->system_error = now_ms < 0 ? EIO : ETIMEDOUT;
            return;
        }
        if (remaining_ms < timeout_ms) {
            timeout_ms = (int)remaining_ms;
        }
    }

    if (!argus_tcp_connect_ipv4(job->address, job->port, timeout_ms, job->result)) {
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
    int64_t scan_started_ms;
    int64_t host_deadline_ms = 0;
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

    scan_started_ms = monotonic_ms();
    if (scan_started_ms < 0) {
        argus_thread_pool_destroy(pool);
        free(jobs);
        return false;
    }
    if (timing->host_timeout_ms > 0) {
        host_deadline_ms = scan_started_ms + timing->host_timeout_ms;
    }

    for (index = 0U; index < ports->count; ++index) {
        jobs[index].address = target->address;
        jobs[index].port = ports->ports[index];
        jobs[index].timeout_ms = timing->initial_rtt_timeout_ms;
        jobs[index].host_deadline_ms = host_deadline_ms;
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
