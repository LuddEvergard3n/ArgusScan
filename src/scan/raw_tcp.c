#include "scan/raw_tcp.h"

#include "net/packet_builder.h"
#include "net/packet_capture.h"
#include "net/packet_parser.h"
#include "net/raw_socket.h"
#include "net/route.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/random.h>
#include <time.h>
#include <unistd.h>

#define ARGUS_RAW_PACKET_CAPACITY 128U

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

static void delay_ms(int milliseconds)
{
    struct timespec requested;
    struct timespec remaining;

    if (milliseconds <= 0) {
        return;
    }
    requested.tv_sec = milliseconds / 1000;
    requested.tv_nsec = (long)(milliseconds % 1000) * 1000000L;
    while (nanosleep(&requested, &remaining) != 0 && errno == EINTR) {
        requested = remaining;
    }
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

static bool addresses_match(
    const ArgusIPv4View *ip,
    struct in_addr source,
    struct in_addr target
)
{
    return memcmp(ip->source, &target.s_addr, 4U) == 0 &&
           memcmp(ip->destination, &source.s_addr, 4U) == 0;
}

static bool icmp_matches_probe(
    const ArgusIcmpView *icmp,
    struct in_addr source,
    struct in_addr target,
    uint16_t source_port,
    uint16_t destination_port
)
{
    const uint8_t *packet = icmp->payload;
    size_t header_length;

    if (icmp->type != 3U ||
        !(icmp->code == 1U || icmp->code == 2U || icmp->code == 3U ||
          icmp->code == 9U || icmp->code == 10U || icmp->code == 13U) ||
        icmp->payload_length < 28U || (packet[0] >> 4U) != 4U || packet[9] != 6U) {
        return false;
    }

    header_length = (size_t)(packet[0] & 0x0fU) * 4U;
    if (header_length < 20U || icmp->payload_length < header_length + 4U) {
        return false;
    }

    return memcmp(&packet[12], &source.s_addr, 4U) == 0 &&
           memcmp(&packet[16], &target.s_addr, 4U) == 0 &&
           (uint16_t)(((uint16_t)packet[header_length] << 8U) |
                      packet[header_length + 1U]) == source_port &&
           (uint16_t)(((uint16_t)packet[header_length + 2U] << 8U) |
                      packet[header_length + 3U]) == destination_port;
}

static bool classify_tcp(
    ArgusRawTcpScanType type,
    const ArgusIPv4View *ip,
    const ArgusTcpView *tcp,
    uint32_t sequence,
    ArgusRawTcpResult *result
)
{
    if (type == ARGUS_SCAN_SYN) {
        if ((tcp->flags & (ARGUS_TCP_SYN | ARGUS_TCP_ACK)) ==
                (ARGUS_TCP_SYN | ARGUS_TCP_ACK) &&
            tcp->acknowledgment == sequence + 1U) {
            result->state = ARGUS_PORT_OPEN;
            result->has_fingerprint = argus_fingerprint_from_syn_ack(
                ip,
                tcp,
                &result->fingerprint
            );
            return true;
        }
        if ((tcp->flags & ARGUS_TCP_RST) != 0U) {
            result->state = ARGUS_PORT_CLOSED;
            return true;
        }
        return false;
    }

    if ((tcp->flags & ARGUS_TCP_RST) == 0U) {
        return false;
    }
    if (type == ARGUS_SCAN_ACK) {
        result->state = ARGUS_PORT_UNFILTERED;
    } else if (type == ARGUS_SCAN_WINDOW) {
        result->state = tcp->window == 0U ? ARGUS_PORT_CLOSED : ARGUS_PORT_OPEN;
    } else {
        result->state = ARGUS_PORT_CLOSED;
    }
    return true;
}

static bool wait_for_probe(
    ArgusPacketCapture *capture,
    struct in_addr source,
    struct in_addr target,
    uint16_t source_port,
    uint16_t destination_port,
    uint32_t sequence,
    int timeout_ms,
    ArgusRawTcpScanType type,
    ArgusRawTcpResult *result
)
{
    int64_t deadline = monotonic_ms() + timeout_ms;

    while (monotonic_ms() < deadline) {
        const uint8_t *packet;
        size_t packet_length;
        ArgusIPv4View ip;
        int remaining = (int)(deadline - monotonic_ms());
        ArgusCaptureStatus capture_status = argus_packet_capture_next_ipv4(
            capture,
            remaining,
            &packet,
            &packet_length
        );

        if (capture_status == ARGUS_CAPTURE_TIMEOUT) {
            return false;
        }
        if (capture_status == ARGUS_CAPTURE_ERROR ||
            !argus_parse_ipv4(packet, packet_length, &ip)) {
            continue;
        }

        if (ip.protocol == 6U && addresses_match(&ip, source, target)) {
            ArgusTcpView tcp;

            if (argus_parse_tcp(&ip, &tcp) &&
                tcp.source_port == destination_port &&
                tcp.destination_port == source_port &&
                classify_tcp(type, &ip, &tcp, sequence, result)) {
                return true;
            }
        } else if (ip.protocol == 1U) {
            ArgusIcmpView icmp;

            if (argus_parse_icmp(&ip, &icmp) &&
                icmp_matches_probe(
                    &icmp,
                    source,
                    target,
                    source_port,
                    destination_port
                )) {
                result->state = ARGUS_PORT_FILTERED;
                return true;
            }
        }
    }
    return false;
}

static bool scan_one(
    ArgusRawSocket *raw,
    ArgusPacketCapture *capture,
    struct in_addr source,
    struct in_addr target,
    uint16_t source_port,
    uint16_t destination_port,
    const ArgusTimingConfig *timing,
    ArgusRawTcpScanType type,
    ArgusRawTcpResult *result
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
    uint8_t packet[ARGUS_RAW_PACKET_CAPACITY];
    size_t packet_length;
    uint32_t sequence = random_u32();
    int attempt;
    int64_t start = monotonic_ms();

    memset(result, 0, sizeof(*result));
    result->port = destination_port;
    result->state = timeout_state(type);

    memset(&spec, 0, sizeof(spec));
    spec.source = source;
    spec.destination = target;
    spec.source_port = source_port;
    spec.destination_port = destination_port;
    spec.sequence = sequence;
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

    if (!argus_build_ipv4_tcp(&spec, packet, sizeof(packet), &packet_length)) {
        return false;
    }

    for (attempt = 0; attempt <= timing->max_retries; ++attempt) {
        if (!argus_raw_socket_send(raw, target, packet, packet_length)) {
            return false;
        }
        if (wait_for_probe(
                capture,
                source,
                target,
                source_port,
                destination_port,
                sequence,
                timing->initial_rtt_timeout_ms,
                type,
                result
            )) {
            int64_t elapsed = monotonic_ms() - start;
            result->latency_ms = elapsed > INT_MAX ? INT_MAX : (int)elapsed;
            return true;
        }
    }

    {
        int64_t elapsed = monotonic_ms() - start;
        result->latency_ms = elapsed > INT_MAX ? INT_MAX : (int)elapsed;
    }
    return true;
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
    struct in_addr source;
    uint16_t source_base;
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

    source_base = (uint16_t)(32768U + (random_u32() % 20000U));
    for (index = 0U; index < ports->count; ++index) {
        uint16_t source_port = (uint16_t)(source_base + (uint16_t)(index % 10000U));

        if (source_port == 0U || !scan_one(
                &raw,
                &capture,
                source,
                target->address,
                source_port,
                ports->ports[index],
                timing,
                type,
                &results[index]
            )) {
            (void)snprintf(error, error_capacity, "probe failed near TCP port %u", ports->ports[index]);
            argus_raw_socket_close(&raw);
            argus_packet_capture_close(&capture);
            return false;
        }
        if (index + 1U < ports->count) {
            delay_ms(timing->scan_delay_ms);
        }
    }

    argus_raw_socket_close(&raw);
    argus_packet_capture_close(&capture);
    return true;
}
