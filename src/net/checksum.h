#ifndef ARGUS_NET_CHECKSUM_H
#define ARGUS_NET_CHECKSUM_H

#include <stddef.h>
#include <stdint.h>

/* RFC 1071 Internet checksum. Multi-byte input is interpreted in network order. */
uint16_t argus_internet_checksum(const void *data, size_t length);

/*
 * IPv4 transport checksum including the RFC 793/RFC 768 pseudo-header.
 * source and destination are four-byte addresses in network byte order.
 */
uint16_t argus_transport_checksum_ipv4(
    const uint8_t source[4],
    const uint8_t destination[4],
    uint8_t protocol,
    const void *segment,
    size_t segment_length
);

#endif

