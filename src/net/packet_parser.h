#ifndef ARGUS_NET_PACKET_PARSER_H
#define ARGUS_NET_PACKET_PARSER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ARGUS_TCP_OPTION_ORDER_CAPACITY 40U

typedef struct {
    uint8_t ttl;
    uint16_t identification;
    bool dont_fragment;
    bool more_fragments;
    uint16_t fragment_offset;
    uint8_t protocol;
    const uint8_t *source;
    const uint8_t *destination;
    const uint8_t *payload;
    size_t header_length;
    size_t payload_length;
} ArgusIPv4View;

typedef struct {
    uint16_t source_port;
    uint16_t destination_port;
    uint32_t sequence;
    uint32_t acknowledgment;
    uint8_t flags;
    uint16_t window;
    const uint8_t *options;
    size_t options_length;
    const uint8_t *payload;
    size_t payload_length;
} ArgusTcpView;

typedef struct {
    uint16_t source_port;
    uint16_t destination_port;
    const uint8_t *payload;
    size_t payload_length;
} ArgusUdpView;

typedef struct {
    uint8_t type;
    uint8_t code;
    const uint8_t *payload;
    size_t payload_length;
} ArgusIcmpView;

typedef struct {
    bool has_mss;
    uint16_t mss;
    bool has_window_scale;
    uint8_t window_scale;
    bool has_sack_permitted;
    bool has_timestamps;
    uint32_t timestamp_value;
    uint32_t timestamp_echo;
    bool has_nop;
    bool has_eol;
    bool malformed;
    uint8_t order[ARGUS_TCP_OPTION_ORDER_CAPACITY];
    size_t order_count;
} ArgusTcpOptions;

bool argus_parse_ipv4(const uint8_t *packet, size_t length, ArgusIPv4View *view);
bool argus_parse_tcp(const ArgusIPv4View *ip, ArgusTcpView *view);
bool argus_parse_udp(const ArgusIPv4View *ip, ArgusUdpView *view);
bool argus_parse_icmp(const ArgusIPv4View *ip, ArgusIcmpView *view);
bool argus_parse_tcp_options(const ArgusTcpView *tcp, ArgusTcpOptions *options);

#endif
