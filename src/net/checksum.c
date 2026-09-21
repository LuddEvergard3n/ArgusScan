#include "net/checksum.h"

#include <limits.h>

static uint32_t add_network_words(uint32_t sum, const uint8_t *bytes, size_t length)
{
    while (length >= 2U) {
        sum += ((uint32_t)bytes[0] << 8U) | (uint32_t)bytes[1];
        bytes += 2;
        length -= 2U;
    }

    if (length == 1U) {
        sum += (uint32_t)bytes[0] << 8U;
    }

    return sum;
}

static uint16_t fold_and_complement(uint32_t sum)
{
    while ((sum >> 16U) != 0U) {
        sum = (sum & UINT16_MAX) + (sum >> 16U);
    }

    return (uint16_t)(~sum & UINT16_MAX);
}

uint16_t argus_internet_checksum(const void *data, size_t length)
{
    if (data == NULL && length != 0U) {
        return 0U;
    }

    return fold_and_complement(add_network_words(0U, (const uint8_t *)data, length));
}

uint16_t argus_transport_checksum_ipv4(
    const uint8_t source[4],
    const uint8_t destination[4],
    uint8_t protocol,
    const void *segment,
    size_t segment_length
)
{
    uint32_t sum = 0U;
    uint8_t pseudo_tail[4];

    if (source == NULL || destination == NULL ||
        (segment == NULL && segment_length != 0U) || segment_length > UINT16_MAX) {
        return 0U;
    }

    pseudo_tail[0] = 0U;
    pseudo_tail[1] = protocol;
    pseudo_tail[2] = (uint8_t)(segment_length >> 8U);
    pseudo_tail[3] = (uint8_t)(segment_length & UINT8_MAX);

    sum = add_network_words(sum, source, 4U);
    sum = add_network_words(sum, destination, 4U);
    sum = add_network_words(sum, pseudo_tail, sizeof(pseudo_tail));
    sum = add_network_words(sum, (const uint8_t *)segment, segment_length);

    return fold_and_complement(sum);
}

