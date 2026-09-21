#include "test.h"

#include "net/checksum.h"
#include "net/packet_builder.h"
#include "net/packet_parser.h"

#include <arpa/inet.h>
#include <string.h>

static void test_tcp_packet(void)
{
    static const uint8_t options[] = {
        2U, 4U, 0x05U, 0xb4U,
        4U, 2U, 1U, 3U,
        3U, 7U, 1U, 1U
    };
    ArgusTcpPacketSpec spec;
    ArgusIPv4View ip;
    ArgusTcpView tcp;
    ArgusTcpOptions parsed_options;
    uint8_t packet[128];
    size_t packet_length = 0U;

    memset(&spec, 0, sizeof(spec));
    ARGUS_CHECK(inet_pton(AF_INET, "192.0.2.10", &spec.source) == 1);
    ARGUS_CHECK(inet_pton(AF_INET, "198.51.100.20", &spec.destination) == 1);
    spec.source_port = 49152U;
    spec.destination_port = 443U;
    spec.sequence = 0x10203040U;
    spec.flags = ARGUS_TCP_SYN;
    spec.window = 64240U;
    spec.ttl = 64U;
    spec.ip_id = 0x1234U;
    spec.dont_fragment = true;
    spec.options = options;
    spec.options_length = sizeof(options);

    ARGUS_CHECK(argus_build_ipv4_tcp(&spec, packet, sizeof(packet), &packet_length));
    ARGUS_CHECK(packet_length == 52U);
    ARGUS_CHECK(argus_internet_checksum(packet, ARGUS_IPV4_HEADER_SIZE) == 0U);
    ARGUS_CHECK(argus_parse_ipv4(packet, packet_length, &ip));
    ARGUS_CHECK(ip.protocol == 6U);
    ARGUS_CHECK(ip.ttl == 64U);
    ARGUS_CHECK(ip.identification == 0x1234U);
    ARGUS_CHECK(ip.dont_fragment);
    ARGUS_CHECK(argus_transport_checksum_ipv4(
        ip.source,
        ip.destination,
        ip.protocol,
        ip.payload,
        ip.payload_length
    ) == 0U);

    ARGUS_CHECK(argus_parse_tcp(&ip, &tcp));
    ARGUS_CHECK(tcp.source_port == 49152U);
    ARGUS_CHECK(tcp.destination_port == 443U);
    ARGUS_CHECK(tcp.sequence == 0x10203040U);
    ARGUS_CHECK(tcp.flags == ARGUS_TCP_SYN);
    ARGUS_CHECK(tcp.window == 64240U);
    ARGUS_CHECK(tcp.options_length == sizeof(options));

    ARGUS_CHECK(argus_parse_tcp_options(&tcp, &parsed_options));
    ARGUS_CHECK(parsed_options.has_mss);
    ARGUS_CHECK(parsed_options.mss == 1460U);
    ARGUS_CHECK(parsed_options.has_sack_permitted);
    ARGUS_CHECK(parsed_options.has_nop);
    ARGUS_CHECK(parsed_options.has_window_scale);
    ARGUS_CHECK(parsed_options.window_scale == 7U);
    ARGUS_CHECK(parsed_options.order_count == 6U);

    packet[0] = 0x44U;
    ARGUS_CHECK(!argus_parse_ipv4(packet, packet_length, &ip));
}

static void test_udp_packet(void)
{
    static const uint8_t payload[] = {0xdeU, 0xadU, 0xbeU, 0xefU};
    ArgusUdpPacketSpec spec;
    ArgusIPv4View ip;
    ArgusUdpView udp;
    uint8_t packet[64];
    size_t packet_length = 0U;

    memset(&spec, 0, sizeof(spec));
    ARGUS_CHECK(inet_pton(AF_INET, "203.0.113.1", &spec.source) == 1);
    ARGUS_CHECK(inet_pton(AF_INET, "203.0.113.2", &spec.destination) == 1);
    spec.source_port = 53000U;
    spec.destination_port = 53U;
    spec.ttl = 64U;
    spec.ip_id = 1U;
    spec.payload = payload;
    spec.payload_length = sizeof(payload);

    ARGUS_CHECK(argus_build_ipv4_udp(&spec, packet, sizeof(packet), &packet_length));
    ARGUS_CHECK(packet_length == 32U);
    ARGUS_CHECK(argus_parse_ipv4(packet, packet_length, &ip));
    ARGUS_CHECK(ip.protocol == 17U);
    ARGUS_CHECK(argus_transport_checksum_ipv4(
        ip.source,
        ip.destination,
        ip.protocol,
        ip.payload,
        ip.payload_length
    ) == 0U);
    ARGUS_CHECK(argus_parse_udp(&ip, &udp));
    ARGUS_CHECK(udp.source_port == 53000U);
    ARGUS_CHECK(udp.destination_port == 53U);
    ARGUS_CHECK(udp.payload_length == sizeof(payload));
    ARGUS_CHECK(memcmp(udp.payload, payload, sizeof(payload)) == 0);
}

static void test_malformed_options(void)
{
    static const uint8_t malformed[] = {2U, 8U, 0U, 0U};
    ArgusTcpView tcp;
    ArgusTcpOptions options;

    memset(&tcp, 0, sizeof(tcp));
    tcp.options = malformed;
    tcp.options_length = sizeof(malformed);
    ARGUS_CHECK(!argus_parse_tcp_options(&tcp, &options));
    ARGUS_CHECK(options.malformed);
}

void test_packet(void)
{
    test_tcp_packet();
    test_udp_packet();
    test_malformed_options();
}

