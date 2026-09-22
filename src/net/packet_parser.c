#include "net/packet_parser.h"

#include <string.h>

static uint16_t read_u16(const uint8_t *input)
{
    return (uint16_t)(((uint16_t)input[0] << 8U) | (uint16_t)input[1]);
}

static uint32_t read_u32(const uint8_t *input)
{
    return ((uint32_t)input[0] << 24U) |
           ((uint32_t)input[1] << 16U) |
           ((uint32_t)input[2] << 8U) |
           (uint32_t)input[3];
}

bool argus_parse_ipv4(const uint8_t *packet, size_t length, ArgusIPv4View *view)
{
    size_t header_length;
    uint16_t total_length;
    uint16_t fragment;

    if (packet == NULL || view == NULL || length < 20U || (packet[0] >> 4U) != 4U) {
        return false;
    }

    header_length = (size_t)(packet[0] & 0x0fU) * 4U;
    total_length = read_u16(&packet[2]);
    if (header_length < 20U || header_length > length ||
        total_length < header_length || (size_t)total_length > length) {
        return false;
    }

    fragment = read_u16(&packet[6]);
    view->ttl = packet[8];
    view->identification = read_u16(&packet[4]);
    view->dont_fragment = (fragment & 0x4000U) != 0U;
    view->more_fragments = (fragment & 0x2000U) != 0U;
    view->fragment_offset = (uint16_t)(fragment & 0x1fffU);
    view->protocol = packet[9];
    view->source = &packet[12];
    view->destination = &packet[16];
    view->payload = &packet[header_length];
    view->header_length = header_length;
    view->payload_length = (size_t)total_length - header_length;
    return true;
}

bool argus_parse_tcp(const ArgusIPv4View *ip, ArgusTcpView *view)
{
    size_t header_length;

    if (ip == NULL || view == NULL || ip->protocol != 6U || ip->payload_length < 20U) {
        return false;
    }

    header_length = (size_t)(ip->payload[12] >> 4U) * 4U;
    if (header_length < 20U || header_length > ip->payload_length) {
        return false;
    }

    view->source_port = read_u16(&ip->payload[0]);
    view->destination_port = read_u16(&ip->payload[2]);
    view->sequence = read_u32(&ip->payload[4]);
    view->acknowledgment = read_u32(&ip->payload[8]);
    view->flags = ip->payload[13];
    view->window = read_u16(&ip->payload[14]);
    view->options = &ip->payload[20];
    view->options_length = header_length - 20U;
    view->payload = &ip->payload[header_length];
    view->payload_length = ip->payload_length - header_length;
    return true;
}

bool argus_parse_udp(const ArgusIPv4View *ip, ArgusUdpView *view)
{
    uint16_t udp_length;

    if (ip == NULL || view == NULL || ip->protocol != 17U || ip->payload_length < 8U) {
        return false;
    }

    udp_length = read_u16(&ip->payload[4]);
    if (udp_length < 8U || (size_t)udp_length > ip->payload_length) {
        return false;
    }

    view->source_port = read_u16(&ip->payload[0]);
    view->destination_port = read_u16(&ip->payload[2]);
    view->payload = &ip->payload[8];
    view->payload_length = (size_t)udp_length - 8U;
    return true;
}

bool argus_parse_icmp(const ArgusIPv4View *ip, ArgusIcmpView *view)
{
    if (ip == NULL || view == NULL || ip->protocol != 1U || ip->payload_length < 8U) {
        return false;
    }

    view->type = ip->payload[0];
    view->code = ip->payload[1];
    view->payload = &ip->payload[8];
    view->payload_length = ip->payload_length - 8U;
    return true;
}

bool argus_parse_tcp_options(const ArgusTcpView *tcp, ArgusTcpOptions *options)
{
    size_t offset = 0U;

    if (tcp == NULL || options == NULL) {
        return false;
    }

    memset(options, 0, sizeof(*options));
    while (offset < tcp->options_length) {
        uint8_t kind = tcp->options[offset];
        uint8_t option_length;

        if (options->order_count < ARGUS_TCP_OPTION_ORDER_CAPACITY) {
            options->order[options->order_count++] = kind;
        }

        if (kind == 0U) {
            options->has_eol = true;
            return true;
        }
        if (kind == 1U) {
            options->has_nop = true;
            ++offset;
            continue;
        }
        if (offset + 2U > tcp->options_length) {
            options->malformed = true;
            return false;
        }

        option_length = tcp->options[offset + 1U];
        if (option_length < 2U || offset + option_length > tcp->options_length) {
            options->malformed = true;
            return false;
        }

        if (kind == 2U && option_length == 4U) {
            options->has_mss = true;
            options->mss = read_u16(&tcp->options[offset + 2U]);
        } else if (kind == 3U && option_length == 3U) {
            options->has_window_scale = true;
            options->window_scale = tcp->options[offset + 2U];
        } else if (kind == 4U && option_length == 2U) {
            options->has_sack_permitted = true;
        } else if (kind == 8U && option_length == 10U) {
            options->has_timestamps = true;
            options->timestamp_value = read_u32(&tcp->options[offset + 2U]);
            options->timestamp_echo = read_u32(&tcp->options[offset + 6U]);
        }
        offset += option_length;
    }

    return true;
}
