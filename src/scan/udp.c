#include "scan/udp.h"

#include "net/packet_builder.h"
#include "net/packet_capture.h"
#include "net/packet_parser.h"
#include "net/raw_socket.h"
#include "net/route.h"
#include "scan/response_classifier.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <time.h>
#include <unistd.h>

#define ARGUS_UDP_PACKET_CAPACITY 128U

typedef struct {
    uint8_t packet[ARGUS_UDP_PACKET_CAPACITY];
    size_t packet_length;
    uint16_t source_port;
    uint16_t destination_port;
    int attempts;
    int64_t started_ms;
    int64_t deadline_ms;
    bool active;
    ArgusUdpResult *result;
} PendingUdpProbe;

static int64_t monotonic_ms(void)
{
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return 0;
    }
    return (int64_t)now.tv_sec * 1000 + (int64_t)now.tv_nsec / 1000000;
}

static uint32_t random_u32(void)
{
    uint32_t value;

    if (getrandom(&value, sizeof(value), 0) == (ssize_t)sizeof(value)) {
        return value;
    }
    return (uint32_t)monotonic_ms() ^ (uint32_t)getpid();
}

static bool prepare_udp_probe(
    struct in_addr source,
    struct in_addr target,
    uint16_t source_port,
    uint16_t destination_port,
    ArgusUdpResult *result,
    PendingUdpProbe *probe
)
{
    ArgusUdpPacketSpec spec;

    memset(result, 0, sizeof(*result));
    result->port = destination_port;
    result->state = ARGUS_PORT_OPEN_FILTERED;
    memset(probe, 0, sizeof(*probe));
    probe->source_port = source_port;
    probe->destination_port = destination_port;
    probe->result = result;

    memset(&spec, 0, sizeof(spec));
    spec.source = source;
    spec.destination = target;
    spec.source_port = source_port;
    spec.destination_port = destination_port;
    spec.ttl = 64U;
    spec.ip_id = (uint16_t)random_u32();
    spec.dont_fragment = true;
    return argus_build_ipv4_udp(
        &spec,
        probe->packet,
        sizeof(probe->packet),
        &probe->packet_length
    );
}

static void finish_udp_probe(PendingUdpProbe *probe, int64_t now)
{
    int64_t elapsed = now - probe->started_ms;

    probe->result->latency_ms = elapsed > INT_MAX ? INT_MAX : (int)elapsed;
    probe->active = false;
}

static bool process_udp_packet(
    const uint8_t *packet,
    size_t packet_length,
    PendingUdpProbe *probes,
    size_t probe_count,
    struct in_addr source,
    struct in_addr target,
    size_t *active_count,
    size_t *completed_count
)
{
    ArgusIPv4View ip;
    ArgusUdpView udp;
    bool has_udp;
    size_t index;

    if (!argus_parse_ipv4(packet, packet_length, &ip)) {
        return false;
    }
    has_udp = ip.protocol == 17U && argus_parse_udp(&ip, &udp);
    if (ip.protocol == 17U && !has_udp) {
        return false;
    }

    for (index = 0U; index < probe_count; ++index) {
        PendingUdpProbe *probe = &probes[index];
        ArgusProbeIdentity identity;
        ArgusResponseClassification classification;

        if (!probe->active) {
            continue;
        }
        if (has_udp && (udp.source_port != probe->destination_port ||
                        udp.destination_port != probe->source_port)) {
            continue;
        }
        identity.source = source;
        identity.target = target;
        identity.source_port = probe->source_port;
        identity.destination_port = probe->destination_port;
        identity.sequence = 0U;
        if (argus_classify_udp_response(&ip, &identity, &classification)) {
            probe->result->state = classification.state;
            finish_udp_probe(probe, monotonic_ms());
            --(*active_count);
            ++(*completed_count);
            return true;
        }
    }
    return false;
}

bool argus_udp_scan(
    const ArgusIPv4Target *target,
    const ArgusPortList *ports,
    const ArgusTimingConfig *timing,
    ArgusUdpResult *results,
    char *error,
    size_t error_capacity
)
{
    ArgusRawSocket raw;
    ArgusPacketCapture capture;
    PendingUdpProbe *probes;
    struct in_addr source;
    uint16_t source_base;
    size_t concurrency;
    size_t next_probe = 0U;
    size_t active_count = 0U;
    size_t completed_count = 0U;
    int64_t scan_started;
    int64_t next_send_at;
    size_t index;

    if (target == NULL || ports == NULL || timing == NULL || results == NULL ||
        error == NULL || error_capacity == 0U || ports->count == 0U) {
        return false;
    }
    error[0] = '\0';
    if (!argus_route_source_ipv4(target->address, &source)) {
        (void)snprintf(error, error_capacity, "could not determine the routed IPv4 source address");
        return false;
    }
    if (argus_packet_capture_open(&capture, source, target->address) != 0) {
        (void)snprintf(error, error_capacity, "capture setup failed: %s", capture.error);
        return false;
    }
    if (!argus_raw_socket_open(&raw)) {
        (void)snprintf(error, error_capacity, "raw socket open failed with system error %d", raw.error_code);
        argus_packet_capture_close(&capture);
        return false;
    }

    probes = calloc(ports->count, sizeof(*probes));
    if (probes == NULL) {
        (void)snprintf(error, error_capacity, "could not allocate UDP probe table");
        argus_raw_socket_close(&raw);
        argus_packet_capture_close(&capture);
        return false;
    }

    source_base = (uint16_t)(20000U + (random_u32() % 10000U));
    for (index = 0U; index < ports->count; ++index) {
        uint16_t source_port = (uint16_t)(source_base + (uint16_t)(index % 28232U));

        if (!prepare_udp_probe(
                source,
                target->address,
                source_port,
                ports->ports[index],
                &results[index],
                &probes[index]
            )) {
            (void)snprintf(error, error_capacity, "could not prepare UDP port %u", ports->ports[index]);
            free(probes);
            argus_raw_socket_close(&raw);
            argus_packet_capture_close(&capture);
            return false;
        }
    }

    concurrency = (size_t)timing->max_parallelism;
    if (concurrency > (size_t)timing->max_outstanding_probes) {
        concurrency = (size_t)timing->max_outstanding_probes;
    }
    if (concurrency > ports->count) {
        concurrency = ports->count;
    }
    if (concurrency > 28232U) {
        concurrency = 28232U;
    }

    scan_started = monotonic_ms();
    next_send_at = scan_started;
    while (completed_count < ports->count) {
        int64_t now = monotonic_ms();
        int64_t wake_at = now + timing->initial_rtt_timeout_ms;
        int wait_ms;
        const uint8_t *packet;
        size_t packet_length;
        ArgusCaptureStatus capture_status;

        if (timing->host_timeout_ms > 0 &&
            now - scan_started >= timing->host_timeout_ms) {
            for (index = 0U; index < ports->count; ++index) {
                if (probes[index].active) {
                    finish_udp_probe(&probes[index], now);
                } else if (probes[index].started_ms == 0) {
                    results[index].latency_ms = (int)(now - scan_started);
                }
            }
            completed_count = ports->count;
            break;
        }

        while (next_probe < ports->count && active_count < concurrency &&
               now >= next_send_at) {
            PendingUdpProbe *probe = &probes[next_probe];

            if (!argus_raw_socket_send(
                    &raw,
                    target->address,
                    probe->packet,
                    probe->packet_length
                )) {
                (void)snprintf(error, error_capacity, "send failed near UDP port %u", probe->destination_port);
                free(probes);
                argus_raw_socket_close(&raw);
                argus_packet_capture_close(&capture);
                return false;
            }
            probe->attempts = 1;
            probe->started_ms = now;
            probe->deadline_ms = now + timing->initial_rtt_timeout_ms;
            probe->active = true;
            ++active_count;
            ++next_probe;
            next_send_at = now + timing->scan_delay_ms;
            if (timing->scan_delay_ms > 0) {
                break;
            }
        }

        for (index = 0U; index < next_probe; ++index) {
            if (probes[index].active && probes[index].deadline_ms < wake_at) {
                wake_at = probes[index].deadline_ms;
            }
        }
        if (next_probe < ports->count && active_count < concurrency && next_send_at < wake_at) {
            wake_at = next_send_at;
        }

        now = monotonic_ms();
        wait_ms = wake_at <= now ? 0 : (int)(wake_at - now);
        if (wait_ms > 0 && active_count > 0U) {
            capture_status = argus_packet_capture_next_ipv4(
                &capture,
                wait_ms,
                &packet,
                &packet_length
            );
            if (capture_status == ARGUS_CAPTURE_ERROR) {
                (void)snprintf(error, error_capacity, "capture failed while UDP probes were pending");
                free(probes);
                argus_raw_socket_close(&raw);
                argus_packet_capture_close(&capture);
                return false;
            }
            if (capture_status == ARGUS_CAPTURE_PACKET) {
                (void)process_udp_packet(
                    packet,
                    packet_length,
                    probes,
                    next_probe,
                    source,
                    target->address,
                    &active_count,
                    &completed_count
                );
            }
        } else if (wait_ms > 0) {
            struct timespec delay;

            delay.tv_sec = wait_ms / 1000;
            delay.tv_nsec = (long)(wait_ms % 1000) * 1000000L;
            (void)nanosleep(&delay, NULL);
        }

        now = monotonic_ms();
        for (index = 0U; index < next_probe; ++index) {
            PendingUdpProbe *probe = &probes[index];

            if (!probe->active || probe->deadline_ms > now) {
                continue;
            }
            if (probe->attempts <= timing->max_retries) {
                if (!argus_raw_socket_send(
                        &raw,
                        target->address,
                        probe->packet,
                        probe->packet_length
                    )) {
                    (void)snprintf(error, error_capacity, "retry failed near UDP port %u", probe->destination_port);
                    free(probes);
                    argus_raw_socket_close(&raw);
                    argus_packet_capture_close(&capture);
                    return false;
                }
                ++probe->attempts;
                probe->deadline_ms = now + timing->initial_rtt_timeout_ms;
            } else {
                finish_udp_probe(probe, now);
                --active_count;
                ++completed_count;
            }
        }
    }

    free(probes);
    argus_raw_socket_close(&raw);
    argus_packet_capture_close(&capture);
    return true;
}
