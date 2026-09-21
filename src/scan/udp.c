#include "scan/udp.h"

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

#define ARGUS_UDP_PACKET_CAPACITY 128U

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

static bool icmp_matches_udp(
    const ArgusIcmpView *icmp,
    struct in_addr source,
    struct in_addr target,
    uint16_t source_port,
    uint16_t destination_port,
    ArgusPortState *state
)
{
    const uint8_t *packet = icmp->payload;
    size_t header_length;

    if (icmp->type != 3U || icmp->payload_length < 28U ||
        (packet[0] >> 4U) != 4U || packet[9] != 17U) {
        return false;
    }

    header_length = (size_t)(packet[0] & 0x0fU) * 4U;
    if (header_length < 20U || icmp->payload_length < header_length + 4U ||
        memcmp(&packet[12], &source.s_addr, 4U) != 0 ||
        memcmp(&packet[16], &target.s_addr, 4U) != 0 ||
        (uint16_t)(((uint16_t)packet[header_length] << 8U) |
                   packet[header_length + 1U]) != source_port ||
        (uint16_t)(((uint16_t)packet[header_length + 2U] << 8U) |
                   packet[header_length + 3U]) != destination_port) {
        return false;
    }

    if (icmp->code == 3U) {
        *state = ARGUS_PORT_CLOSED;
        return true;
    }
    if (icmp->code == 1U || icmp->code == 2U || icmp->code == 9U ||
        icmp->code == 10U || icmp->code == 13U) {
        *state = ARGUS_PORT_FILTERED;
        return true;
    }
    return false;
}

static bool wait_for_udp(
    ArgusPacketCapture *capture,
    struct in_addr source,
    struct in_addr target,
    uint16_t source_port,
    uint16_t destination_port,
    int timeout_ms,
    ArgusPortState *state
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

        if (ip.protocol == 17U &&
            memcmp(ip.source, &target.s_addr, 4U) == 0 &&
            memcmp(ip.destination, &source.s_addr, 4U) == 0) {
            ArgusUdpView udp;

            if (argus_parse_udp(&ip, &udp) &&
                udp.source_port == destination_port && udp.destination_port == source_port) {
                *state = ARGUS_PORT_OPEN;
                return true;
            }
        } else if (ip.protocol == 1U) {
            ArgusIcmpView icmp;

            if (argus_parse_icmp(&ip, &icmp) &&
                icmp_matches_udp(
                    &icmp,
                    source,
                    target,
                    source_port,
                    destination_port,
                    state
                )) {
                return true;
            }
        }
    }
    return false;
}

static bool scan_one_udp(
    ArgusRawSocket *raw,
    ArgusPacketCapture *capture,
    struct in_addr source,
    struct in_addr target,
    uint16_t source_port,
    uint16_t destination_port,
    const ArgusTimingConfig *timing,
    ArgusUdpResult *result
)
{
    ArgusUdpPacketSpec spec;
    uint8_t packet[ARGUS_UDP_PACKET_CAPACITY];
    size_t packet_length;
    int attempt;
    int64_t start = monotonic_ms();

    memset(result, 0, sizeof(*result));
    result->port = destination_port;
    result->state = ARGUS_PORT_OPEN_FILTERED;

    memset(&spec, 0, sizeof(spec));
    spec.source = source;
    spec.destination = target;
    spec.source_port = source_port;
    spec.destination_port = destination_port;
    spec.ttl = 64U;
    spec.ip_id = (uint16_t)random_u32();
    spec.dont_fragment = true;
    if (!argus_build_ipv4_udp(&spec, packet, sizeof(packet), &packet_length)) {
        return false;
    }

    for (attempt = 0; attempt <= timing->max_retries; ++attempt) {
        if (!argus_raw_socket_send(raw, target, packet, packet_length)) {
            return false;
        }
        if (wait_for_udp(
                capture,
                source,
                target,
                source_port,
                destination_port,
                timing->initial_rtt_timeout_ms,
                &result->state
            )) {
            break;
        }
    }

    {
        int64_t elapsed = monotonic_ms() - start;
        result->latency_ms = elapsed > INT_MAX ? INT_MAX : (int)elapsed;
    }
    return true;
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
    struct in_addr source;
    uint16_t source_base;
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

    source_base = (uint16_t)(32768U + (random_u32() % 20000U));
    for (index = 0U; index < ports->count; ++index) {
        uint16_t source_port = (uint16_t)(source_base + (uint16_t)(index % 10000U));

        if (!scan_one_udp(
                &raw,
                &capture,
                source,
                target->address,
                source_port,
                ports->ports[index],
                timing,
                &results[index]
            )) {
            (void)snprintf(error, error_capacity, "UDP probe failed near port %u", ports->ports[index]);
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

