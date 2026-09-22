#include "scan/raw_tcp.h"

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

#define ARGUS_RAW_PACKET_CAPACITY 128U

typedef struct {
    uint8_t packet[ARGUS_RAW_PACKET_CAPACITY];
    size_t packet_length;
    uint16_t source_port;
    uint16_t destination_port;
    uint32_t sequence;
    int attempts;
    int64_t started_ms;
    int64_t deadline_ms;
    bool active;
    ArgusRawTcpResult *result;
} PendingProbe;

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

static uint8_t flags_for_scan(ArgusRawTcpScanType type)
{
    switch (type) {
    case ARGUS_SCAN_SYN:
        return ARGUS_TCP_SYN;
    case ARGUS_SCAN_FIN:
        return ARGUS_TCP_FIN;
    case ARGUS_SCAN_NULL:
        return 0U;
    case ARGUS_SCAN_XMAS:
        return ARGUS_TCP_FIN | ARGUS_TCP_PSH | ARGUS_TCP_URG;
    case ARGUS_SCAN_ACK:
    case ARGUS_SCAN_WINDOW:
        return ARGUS_TCP_ACK;
    default:
        return 0U;
    }
}

static ArgusPortState timeout_state(ArgusRawTcpScanType type)
{
    if (type == ARGUS_SCAN_FIN || type == ARGUS_SCAN_NULL || type == ARGUS_SCAN_XMAS) {
        return ARGUS_PORT_OPEN_FILTERED;
    }
    return ARGUS_PORT_FILTERED;
}

static bool prepare_probe(
    struct in_addr source,
    struct in_addr target,
    uint16_t source_port,
    uint16_t destination_port,
    ArgusRawTcpScanType type,
    ArgusRawTcpResult *result,
    PendingProbe *probe
)
{
    static const uint8_t syn_options[] = {
        2U, 4U, 0x05U, 0xb4U,
        4U, 2U,
        8U, 10U, 0U, 0U, 0U, 1U, 0U, 0U, 0U, 0U,
        1U,
        3U, 3U, 7U
    };
    ArgusTcpPacketSpec spec;

    memset(result, 0, sizeof(*result));
    result->port = destination_port;
    result->state = timeout_state(type);
    memset(probe, 0, sizeof(*probe));
    probe->source_port = source_port;
    probe->destination_port = destination_port;
    probe->sequence = random_u32();
    probe->result = result;

    memset(&spec, 0, sizeof(spec));
    spec.source = source;
    spec.destination = target;
    spec.source_port = source_port;
    spec.destination_port = destination_port;
    spec.sequence = probe->sequence;
    spec.acknowledgment = type == ARGUS_SCAN_ACK || type == ARGUS_SCAN_WINDOW
        ? random_u32()
        : 0U;
    spec.flags = flags_for_scan(type);
    spec.window = 64240U;
    spec.ttl = 64U;
    spec.ip_id = (uint16_t)random_u32();
    spec.dont_fragment = true;
    if (type == ARGUS_SCAN_SYN) {
        spec.options = syn_options;
        spec.options_length = sizeof(syn_options);
    }

    return argus_build_ipv4_tcp(
        &spec,
        probe->packet,
        sizeof(probe->packet),
        &probe->packet_length
    );
}

static void finish_probe(PendingProbe *probe, int64_t now)
{
    int64_t elapsed = now - probe->started_ms;

    probe->result->latency_ms = elapsed > INT_MAX ? INT_MAX : (int)elapsed;
    probe->active = false;
}

static bool process_captured_packet(
    const uint8_t *packet,
    size_t packet_length,
    PendingProbe *probes,
    size_t probe_count,
    struct in_addr source,
    struct in_addr target,
    ArgusRawTcpScanType type,
    size_t *active_count,
    size_t *completed_count
)
{
    ArgusIPv4View ip;
    ArgusTcpView tcp;
    bool has_tcp;
    size_t index;

    if (!argus_parse_ipv4(packet, packet_length, &ip)) {
        return false;
    }
    has_tcp = ip.protocol == 6U && argus_parse_tcp(&ip, &tcp);
    if (ip.protocol == 6U && !has_tcp) {
        return false;
    }

    for (index = 0U; index < probe_count; ++index) {
        PendingProbe *probe = &probes[index];
        ArgusProbeIdentity identity;
        ArgusResponseClassification classification;

        if (!probe->active) {
            continue;
        }
        if (has_tcp && (tcp.source_port != probe->destination_port ||
                        tcp.destination_port != probe->source_port)) {
            continue;
        }
        identity.source = source;
        identity.target = target;
        identity.source_port = probe->source_port;
        identity.destination_port = probe->destination_port;
        identity.sequence = probe->sequence;
        if (argus_classify_tcp_response(&ip, &identity, type, &classification)) {
            probe->result->state = classification.state;
            probe->result->has_fingerprint = classification.has_fingerprint;
            if (classification.has_fingerprint) {
                probe->result->fingerprint = classification.fingerprint;
            }
            finish_probe(probe, monotonic_ms());
            --(*active_count);
            ++(*completed_count);
            return true;
        }
    }
    return false;
}

const char *argus_raw_tcp_scan_name(ArgusRawTcpScanType type)
{
    static const char *const names[] = {"syn", "fin", "null", "xmas", "ack", "window"};

    if (type < ARGUS_SCAN_SYN || type > ARGUS_SCAN_WINDOW) {
        return "unknown";
    }
    return names[(int)type];
}

bool argus_raw_tcp_scan_parse(const char *text, ArgusRawTcpScanType *type)
{
    int index;

    if (text == NULL || type == NULL) {
        return false;
    }
    for (index = 0; index <= (int)ARGUS_SCAN_WINDOW; ++index) {
        ArgusRawTcpScanType candidate = (ArgusRawTcpScanType)index;
        if (strcmp(text, argus_raw_tcp_scan_name(candidate)) == 0) {
            *type = candidate;
            return true;
        }
    }
    return false;
}

bool argus_raw_tcp_scan(
    const ArgusIPv4Target *target,
    const ArgusPortList *ports,
    const ArgusTimingConfig *timing,
    ArgusRawTcpScanType type,
    ArgusRawTcpResult *results,
    char *error,
    size_t error_capacity
)
{
    ArgusRawSocket raw;
    ArgusPacketCapture capture;
    PendingProbe *probes;
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
        error == NULL || error_capacity == 0U || ports->count == 0U ||
        type < ARGUS_SCAN_SYN || type > ARGUS_SCAN_WINDOW) {
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
        (void)snprintf(error, error_capacity, "could not allocate raw probe table");
        argus_raw_socket_close(&raw);
        argus_packet_capture_close(&capture);
        return false;
    }

    source_base = (uint16_t)(20000U + (random_u32() % 10000U));
    for (index = 0U; index < ports->count; ++index) {
        uint16_t source_port = (uint16_t)(source_base + (uint16_t)(index % 28232U));

        if (source_port == 0U || !prepare_probe(
                source,
                target->address,
                source_port,
                ports->ports[index],
                type,
                &results[index],
                &probes[index]
            )) {
            (void)snprintf(error, error_capacity, "could not prepare TCP port %u", ports->ports[index]);
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
                    finish_probe(&probes[index], now);
                } else if (probes[index].started_ms == 0) {
                    results[index].latency_ms = (int)(now - scan_started);
                }
            }
            completed_count = ports->count;
            break;
        }

        while (next_probe < ports->count && active_count < concurrency &&
               now >= next_send_at) {
            PendingProbe *probe = &probes[next_probe];

            if (!argus_raw_socket_send(
                    &raw,
                    target->address,
                    probe->packet,
                    probe->packet_length
                )) {
                (void)snprintf(error, error_capacity, "send failed near TCP port %u", probe->destination_port);
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
                (void)snprintf(error, error_capacity, "capture failed while probes were pending");
                free(probes);
                argus_raw_socket_close(&raw);
                argus_packet_capture_close(&capture);
                return false;
            }
            if (capture_status == ARGUS_CAPTURE_PACKET) {
                (void)process_captured_packet(
                    packet,
                    packet_length,
                    probes,
                    next_probe,
                    source,
                    target->address,
                    type,
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
            PendingProbe *probe = &probes[index];

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
                    (void)snprintf(error, error_capacity, "retry failed near TCP port %u", probe->destination_port);
                    free(probes);
                    argus_raw_socket_close(&raw);
                    argus_packet_capture_close(&capture);
                    return false;
                }
                ++probe->attempts;
                probe->deadline_ms = now + timing->initial_rtt_timeout_ms;
            } else {
                finish_probe(probe, now);
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
