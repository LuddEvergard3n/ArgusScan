#include "net/packet_builder.h"

#include "net/checksum.h"

#include <limits.h>
#include <string.h>

static void write_u16(uint8_t *output, uint16_t value)
{
    output[0] = (uint8_t)(value >> 8U);
    output[1] = (uint8_t)(value & UINT8_MAX);
}

static void write_u32(uint8_t *output, uint32_t value)
{
    output[0] = (uint8_t)(value >> 24U);
    output[1] = (uint8_t)((value >> 16U) & UINT8_MAX);
    output[2] = (uint8_t)((value >> 8U) & UINT8_MAX);
    output[3] = (uint8_t)(value & UINT8_MAX);
}

static void write_ipv4_header(
    uint8_t *output,
    uint16_t total_length,
    uint16_t ip_id,
    bool dont_fragment,
    uint8_t ttl,
    uint8_t protocol,
    struct in_addr source,
    struct in_addr destination
)
{
    uint16_t checksum;

    memset(output, 0, ARGUS_IPV4_HEADER_SIZE);
    output[0] = 0x45U;
    write_u16(&output[2], total_length);
    write_u16(&output[4], ip_id);
    write_u16(&output[6], dont_fragment ? 0x4000U : 0U);
    output[8] = ttl;
    output[9] = protocol;
    memcpy(&output[12], &source.s_addr, 4U);
    memcpy(&output[16], &destination.s_addr, 4U);
    checksum = argus_internet_checksum(output, ARGUS_IPV4_HEADER_SIZE);
    write_u16(&output[10], checksum);
}

bool argus_build_ipv4_tcp(
    const ArgusTcpPacketSpec *spec,
    uint8_t *output,
    size_t output_capacity,
    size_t *output_length
)
{
    uint8_t *tcp;
    const uint8_t *source;
    const uint8_t *destination;
    size_t tcp_length;
    size_t total_length;
    uint16_t checksum;

    if (spec == NULL || output == NULL || output_length == NULL ||
        spec->source_port == 0U || spec->destination_port == 0U || spec->ttl == 0U ||
        spec->options_length > ARGUS_TCP_MAX_OPTIONS_SIZE ||
        spec->options_length % 4U != 0U ||
        (spec->options == NULL && spec->options_length != 0U) ||
        (spec->payload == NULL && spec->payload_length != 0U)) {
        return false;
    }

    tcp_length = ARGUS_TCP_MIN_HEADER_SIZE + spec->options_length + spec->payload_length;
    total_length = ARGUS_IPV4_HEADER_SIZE + tcp_length;
    if (total_length > UINT16_MAX || output_capacity < total_length) {
        return false;
    }

    memset(output, 0, total_length);
    write_ipv4_header(
        output,
        (uint16_t)total_length,
        spec->ip_id,
        spec->dont_fragment,
        spec->ttl,
        6U,
        spec->source,
        spec->destination
    );

    tcp = output + ARGUS_IPV4_HEADER_SIZE;
    write_u16(&tcp[0], spec->source_port);
    write_u16(&tcp[2], spec->destination_port);
    write_u32(&tcp[4], spec->sequence);
    write_u32(&tcp[8], spec->acknowledgment);
    tcp[12] = (uint8_t)(((ARGUS_TCP_MIN_HEADER_SIZE + spec->options_length) / 4U) << 4U);
    tcp[13] = spec->flags;
    write_u16(&tcp[14], spec->window);

    if (spec->options_length != 0U) {
        memcpy(&tcp[ARGUS_TCP_MIN_HEADER_SIZE], spec->options, spec->options_length);
    }
    if (spec->payload_length != 0U) {
        memcpy(
            &tcp[ARGUS_TCP_MIN_HEADER_SIZE + spec->options_length],
            spec->payload,
            spec->payload_length
        );
    }

    source = (const uint8_t *)&spec->source.s_addr;
    destination = (const uint8_t *)&spec->destination.s_addr;
    checksum = argus_transport_checksum_ipv4(source, destination, 6U, tcp, tcp_length);
    write_u16(&tcp[16], checksum);
    *output_length = total_length;
    return true;
}

bool argus_build_ipv4_udp(
    const ArgusUdpPacketSpec *spec,
    uint8_t *output,
    size_t output_capacity,
    size_t *output_length
)
{
    uint8_t *udp;
    const uint8_t *source;
    const uint8_t *destination;
    size_t udp_length;
    size_t total_length;
    uint16_t checksum;

    if (spec == NULL || output == NULL || output_length == NULL ||
        spec->source_port == 0U || spec->destination_port == 0U || spec->ttl == 0U ||
        (spec->payload == NULL && spec->payload_length != 0U)) {
        return false;
    }

    udp_length = ARGUS_UDP_HEADER_SIZE + spec->payload_length;
    total_length = ARGUS_IPV4_HEADER_SIZE + udp_length;
    if (udp_length > UINT16_MAX || total_length > UINT16_MAX || output_capacity < total_length) {
        return false;
    }

    memset(output, 0, total_length);
    write_ipv4_header(
        output,
        (uint16_t)total_length,
        spec->ip_id,
        spec->dont_fragment,
        spec->ttl,
        17U,
        spec->source,
        spec->destination
    );

    udp = output + ARGUS_IPV4_HEADER_SIZE;
    write_u16(&udp[0], spec->source_port);
    write_u16(&udp[2], spec->destination_port);
    write_u16(&udp[4], (uint16_t)udp_length);
    if (spec->payload_length != 0U) {
        memcpy(&udp[ARGUS_UDP_HEADER_SIZE], spec->payload, spec->payload_length);
    }

    source = (const uint8_t *)&spec->source.s_addr;
    destination = (const uint8_t *)&spec->destination.s_addr;
    checksum = argus_transport_checksum_ipv4(source, destination, 17U, udp, udp_length);
    if (checksum == 0U) {
        checksum = UINT16_MAX;
    }
    write_u16(&udp[6], checksum);
    *output_length = total_length;
    return true;
}

