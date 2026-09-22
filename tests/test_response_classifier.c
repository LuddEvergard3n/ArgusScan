#include "test.h"

#include "net/packet_builder.h"
#include "net/packet_parser.h"
#include "engine/timing.h"
#include "scan/response_classifier.h"

#include <arpa/inet.h>
#include <string.h>

static bool parse_tcp_fixture(
    const ArgusProbeIdentity *probe,
    uint16_t remote_port,
    uint8_t flags,
    uint32_t acknowledgment,
    uint16_t window,
    uint8_t *packet,
    size_t *packet_length,
    ArgusIPv4View *ip
)
{
    static const uint8_t options[] = {
        2U, 4U, 0x05U, 0xb4U, 4U, 2U,
        8U, 10U, 0U, 0U, 0U, 1U, 0U, 0U, 0U, 0U,
        1U, 3U, 3U, 7U
    };
    ArgusTcpPacketSpec spec;

    memset(&spec, 0, sizeof(spec));
    spec.source = probe->target;
    spec.destination = probe->source;
    spec.source_port = remote_port;
    spec.destination_port = probe->source_port;
    spec.sequence = 0x55667788U;
    spec.acknowledgment = acknowledgment;
    spec.flags = flags;
    spec.window = window;
    spec.ttl = 64U;
    spec.ip_id = 0x2345U;
    spec.dont_fragment = true;
    if ((flags & ARGUS_TCP_SYN) != 0U) {
        spec.options = options;
        spec.options_length = sizeof(options);
    }
    return argus_build_ipv4_tcp(&spec, packet, 128U, packet_length) &&
        argus_parse_ipv4(packet, *packet_length, ip);
}

static bool parse_udp_fixture(
    const ArgusProbeIdentity *probe,
    uint16_t remote_port,
    uint8_t *packet,
    size_t *packet_length,
    ArgusIPv4View *ip
)
{
    static const uint8_t payload[] = {0x4fU, 0x4bU};
    ArgusUdpPacketSpec spec;

    memset(&spec, 0, sizeof(spec));
    spec.source = probe->target;
    spec.destination = probe->source;
    spec.source_port = remote_port;
    spec.destination_port = probe->source_port;
    spec.ttl = 64U;
    spec.ip_id = 0x3456U;
    spec.payload = payload;
    spec.payload_length = sizeof(payload);
    return argus_build_ipv4_udp(&spec, packet, 128U, packet_length) &&
        argus_parse_ipv4(packet, *packet_length, ip);
}

static bool parse_icmp_fixture(
    const ArgusProbeIdentity *probe,
    uint8_t embedded_protocol,
    uint8_t code,
    uint8_t *packet,
    size_t packet_capacity,
    ArgusIPv4View *ip
)
{
    uint8_t *icmp;
    uint8_t *embedded;
    const size_t packet_length = 56U;

    if (packet_capacity < packet_length) {
        return false;
    }
    memset(packet, 0, packet_length);
    packet[0] = 0x45U;
    packet[2] = 0U;
    packet[3] = (uint8_t)packet_length;
    packet[8] = 64U;
    packet[9] = 1U;
    memcpy(&packet[12], &probe->target.s_addr, 4U);
    memcpy(&packet[16], &probe->source.s_addr, 4U);

    icmp = &packet[20];
    icmp[0] = 3U;
    icmp[1] = code;
    embedded = &icmp[8];
    embedded[0] = 0x45U;
    embedded[2] = 0U;
    embedded[3] = 28U;
    embedded[8] = 64U;
    embedded[9] = embedded_protocol;
    memcpy(&embedded[12], &probe->source.s_addr, 4U);
    memcpy(&embedded[16], &probe->target.s_addr, 4U);
    embedded[20] = (uint8_t)(probe->source_port >> 8U);
    embedded[21] = (uint8_t)probe->source_port;
    embedded[22] = (uint8_t)(probe->destination_port >> 8U);
    embedded[23] = (uint8_t)probe->destination_port;
    return argus_parse_ipv4(packet, packet_length, ip);
}

static ArgusProbeIdentity make_probe(uint16_t destination_port)
{
    ArgusProbeIdentity probe;

    memset(&probe, 0, sizeof(probe));
    (void)inet_pton(AF_INET, "192.0.2.10", &probe.source);
    (void)inet_pton(AF_INET, "198.51.100.20", &probe.target);
    probe.source_port = 41000U;
    probe.destination_port = destination_port;
    probe.sequence = 0x10203040U;
    return probe;
}

static void test_tcp_classification(void)
{
    ArgusProbeIdentity probe = make_probe(443U);
    ArgusResponseClassification result;
    ArgusIPv4View ip;
    uint8_t packet[128];
    size_t packet_length;

    ARGUS_CHECK(parse_tcp_fixture(
        &probe, 443U, ARGUS_TCP_SYN | ARGUS_TCP_ACK, probe.sequence + 1U,
        64240U, packet, &packet_length, &ip
    ));
    ARGUS_CHECK(argus_classify_tcp_response(&ip, &probe, ARGUS_SCAN_SYN, &result));
    ARGUS_CHECK(result.state == ARGUS_PORT_OPEN);
    ARGUS_CHECK(result.has_fingerprint);

    ARGUS_CHECK(parse_tcp_fixture(
        &probe, 443U, ARGUS_TCP_SYN | ARGUS_TCP_ACK, probe.sequence + 2U,
        64240U, packet, &packet_length, &ip
    ));
    ARGUS_CHECK(!argus_classify_tcp_response(&ip, &probe, ARGUS_SCAN_SYN, &result));

    ARGUS_CHECK(parse_tcp_fixture(
        &probe, 443U, ARGUS_TCP_RST | ARGUS_TCP_ACK, probe.sequence + 1U,
        0U, packet, &packet_length, &ip
    ));
    ARGUS_CHECK(argus_classify_tcp_response(&ip, &probe, ARGUS_SCAN_SYN, &result));
    ARGUS_CHECK(result.state == ARGUS_PORT_CLOSED);
    ARGUS_CHECK(argus_classify_tcp_response(&ip, &probe, ARGUS_SCAN_ACK, &result));
    ARGUS_CHECK(result.state == ARGUS_PORT_UNFILTERED);
    ARGUS_CHECK(argus_classify_tcp_response(&ip, &probe, ARGUS_SCAN_WINDOW, &result));
    ARGUS_CHECK(result.state == ARGUS_PORT_CLOSED);

    ARGUS_CHECK(parse_tcp_fixture(
        &probe, 443U, ARGUS_TCP_RST, 0U, 1024U,
        packet, &packet_length, &ip
    ));
    ARGUS_CHECK(argus_classify_tcp_response(&ip, &probe, ARGUS_SCAN_WINDOW, &result));
    ARGUS_CHECK(result.state == ARGUS_PORT_OPEN);

    ARGUS_CHECK(parse_icmp_fixture(&probe, 6U, 13U, packet, sizeof(packet), &ip));
    ARGUS_CHECK(argus_classify_tcp_response(&ip, &probe, ARGUS_SCAN_SYN, &result));
    ARGUS_CHECK(result.state == ARGUS_PORT_FILTERED);
}

static void test_udp_classification(void)
{
    ArgusProbeIdentity probe = make_probe(53U);
    ArgusResponseClassification result;
    ArgusIPv4View ip;
    uint8_t packet[128];
    size_t packet_length;

    ARGUS_CHECK(parse_udp_fixture(&probe, 53U, packet, &packet_length, &ip));
    ARGUS_CHECK(argus_classify_udp_response(&ip, &probe, &result));
    ARGUS_CHECK(result.state == ARGUS_PORT_OPEN);

    packet[6] = 0x20U;
    packet[7] = 0U;
    ARGUS_CHECK(argus_parse_ipv4(packet, packet_length, &ip));
    ARGUS_CHECK(!argus_classify_udp_response(&ip, &probe, &result));

    ARGUS_CHECK(parse_udp_fixture(&probe, 54U, packet, &packet_length, &ip));
    ARGUS_CHECK(!argus_classify_udp_response(&ip, &probe, &result));

    ARGUS_CHECK(parse_icmp_fixture(&probe, 17U, 3U, packet, sizeof(packet), &ip));
    ARGUS_CHECK(argus_classify_udp_response(&ip, &probe, &result));
    ARGUS_CHECK(result.state == ARGUS_PORT_CLOSED);

    ARGUS_CHECK(parse_icmp_fixture(&probe, 17U, 10U, packet, sizeof(packet), &ip));
    ARGUS_CHECK(argus_classify_udp_response(&ip, &probe, &result));
    ARGUS_CHECK(result.state == ARGUS_PORT_FILTERED);
}

static void test_reordering_duplicates_and_truncation(void)
{
    ArgusProbeIdentity probes[] = {make_probe(80U), make_probe(443U)};
    bool active[] = {true, true};
    ArgusResponseClassification result;
    ArgusIPv4View ip;
    uint8_t packet[128];
    size_t packet_length;
    size_t completed = 0U;
    size_t index;

    ARGUS_CHECK(parse_tcp_fixture(
        &probes[1], 443U, ARGUS_TCP_SYN | ARGUS_TCP_ACK,
        probes[1].sequence + 1U, 64240U, packet, &packet_length, &ip
    ));
    for (index = 0U; index < 2U; ++index) {
        if (active[index] && argus_classify_tcp_response(
                &ip, &probes[index], ARGUS_SCAN_SYN, &result)) {
            active[index] = false;
            ++completed;
            break;
        }
    }
    ARGUS_CHECK(completed == 1U && active[0] && !active[1]);

    for (index = 0U; index < 2U; ++index) {
        if (active[index] && argus_classify_tcp_response(
                &ip, &probes[index], ARGUS_SCAN_SYN, &result)) {
            active[index] = false;
            ++completed;
        }
    }
    ARGUS_CHECK(completed == 1U);

    ARGUS_CHECK(parse_tcp_fixture(
        &probes[0], 80U, ARGUS_TCP_SYN | ARGUS_TCP_ACK,
        probes[0].sequence + 1U, 64240U, packet, &packet_length, &ip
    ));
    ARGUS_CHECK(argus_classify_tcp_response(&ip, &probes[0], ARGUS_SCAN_SYN, &result));
    active[0] = false;
    ++completed;
    ARGUS_CHECK(completed == 2U && !active[0] && !active[1]);

    packet[6] = 0x20U;
    packet[7] = 0U;
    ARGUS_CHECK(argus_parse_ipv4(packet, packet_length, &ip));
    ARGUS_CHECK(ip.more_fragments);
    ARGUS_CHECK(!argus_classify_tcp_response(
        &ip, &probes[0], ARGUS_SCAN_SYN, &result
    ));
    packet[6] = 0U;
    packet[7] = 1U;
    ARGUS_CHECK(argus_parse_ipv4(packet, packet_length, &ip));
    ARGUS_CHECK(ip.fragment_offset == 1U);
    ARGUS_CHECK(!argus_classify_tcp_response(
        &ip, &probes[0], ARGUS_SCAN_SYN, &result
    ));
    packet[6] = 0x40U;
    packet[7] = 0U;

    ARGUS_CHECK(!argus_parse_ipv4(packet, 19U, &ip));
    packet[2] = 0U;
    packet[3] = (uint8_t)(packet_length + 1U);
    ARGUS_CHECK(!argus_parse_ipv4(packet, packet_length, &ip));
}

static void test_probe_profile_validation(void)
{
    ArgusIPv4Target target;
    ArgusTimingConfig timing;
    ArgusRawTcpResult result;
    uint16_t port = 80U;
    ArgusPortList ports = {&port, 1U};
    char error[64];

    memset(&target, 0, sizeof(target));
    ARGUS_CHECK(argus_timing_config(ARGUS_TIMING_NORMAL, &timing));
    ARGUS_CHECK(!argus_raw_tcp_scan_profile(
        &target,
        &ports,
        &timing,
        ARGUS_SCAN_SYN,
        (ArgusTcpProbeProfile)99,
        &result,
        error,
        sizeof(error)
    ));
    ARGUS_CHECK(!argus_raw_tcp_scan_profile(
        &target,
        &ports,
        &timing,
        ARGUS_SCAN_FIN,
        ARGUS_TCP_PROBE_MINIMAL,
        &result,
        error,
        sizeof(error)
    ));
}

void test_response_classifier(void)
{
    test_tcp_classification();
    test_udp_classification();
    test_reordering_duplicates_and_truncation();
    test_probe_profile_validation();
}
