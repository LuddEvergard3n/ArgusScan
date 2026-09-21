#ifndef ARGUS_NET_PACKET_BUILDER_H
#define ARGUS_NET_PACKET_BUILDER_H

#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ARGUS_IPV4_HEADER_SIZE 20U
#define ARGUS_TCP_MIN_HEADER_SIZE 20U
#define ARGUS_UDP_HEADER_SIZE 8U
#define ARGUS_TCP_MAX_OPTIONS_SIZE 40U

#define ARGUS_TCP_FIN 0x01U
#define ARGUS_TCP_SYN 0x02U
#define ARGUS_TCP_RST 0x04U
#define ARGUS_TCP_PSH 0x08U
#define ARGUS_TCP_ACK 0x10U
#define ARGUS_TCP_URG 0x20U
#define ARGUS_TCP_ECE 0x40U
#define ARGUS_TCP_CWR 0x80U

typedef struct {
    struct in_addr source;
    struct in_addr destination;
    uint16_t source_port;
    uint16_t destination_port;
    uint32_t sequence;
    uint32_t acknowledgment;
    uint8_t flags;
    uint16_t window;
    uint8_t ttl;
    uint16_t ip_id;
    bool dont_fragment;
    const uint8_t *options;
    size_t options_length;
    const uint8_t *payload;
    size_t payload_length;
} ArgusTcpPacketSpec;

typedef struct {
    struct in_addr source;
    struct in_addr destination;
    uint16_t source_port;
    uint16_t destination_port;
    uint8_t ttl;
    uint16_t ip_id;
    bool dont_fragment;
    const uint8_t *payload;
    size_t payload_length;
} ArgusUdpPacketSpec;

bool argus_build_ipv4_tcp(
    const ArgusTcpPacketSpec *spec,
    uint8_t *output,
    size_t output_capacity,
    size_t *output_length
);

bool argus_build_ipv4_udp(
    const ArgusUdpPacketSpec *spec,
    uint8_t *output,
    size_t output_capacity,
    size_t *output_length
);

#endif

