#include "scan/response_classifier.h"

#include "net/packet_builder.h"

#include <stddef.h>
#include <string.h>

static uint16_t read_u16(const uint8_t *input)
{
    return (uint16_t)(((uint16_t)input[0] << 8U) | (uint16_t)input[1]);
}

static bool response_addresses_match(
    const ArgusIPv4View *ip,
    const ArgusProbeIdentity *probe
)
{
    return memcmp(ip->source, &probe->target.s_addr, 4U) == 0 &&
        memcmp(ip->destination, &probe->source.s_addr, 4U) == 0;
}

static bool icmp_embeds_probe(
    const ArgusIcmpView *icmp,
    const ArgusProbeIdentity *probe,
    uint8_t protocol
)
{
    const uint8_t *packet = icmp->payload;
    size_t header_length;

    if (icmp->type != 3U || icmp->payload_length < 28U ||
        (packet[0] >> 4U) != 4U || packet[9] != protocol) {
        return false;
    }
    header_length = (size_t)(packet[0] & 0x0fU) * 4U;
    return header_length >= 20U &&
        icmp->payload_length >= header_length + 4U &&
        memcmp(&packet[12], &probe->source.s_addr, 4U) == 0 &&
        memcmp(&packet[16], &probe->target.s_addr, 4U) == 0 &&
        read_u16(&packet[header_length]) == probe->source_port &&
        read_u16(&packet[header_length + 2U]) == probe->destination_port;
}

static bool prohibitive_icmp_code(uint8_t code)
{
    return code == 1U || code == 2U || code == 9U || code == 10U || code == 13U;
}

bool argus_classify_tcp_response(
    const ArgusIPv4View *ip,
    const ArgusProbeIdentity *probe,
    ArgusRawTcpScanType type,
    ArgusResponseClassification *classification
)
{
    if (ip == NULL || probe == NULL || classification == NULL ||
        type < ARGUS_SCAN_SYN || type > ARGUS_SCAN_WINDOW) {
        return false;
    }
    memset(classification, 0, sizeof(*classification));
    if (ip->more_fragments || ip->fragment_offset != 0U) {
        return false;
    }

    if (ip->protocol == 6U && response_addresses_match(ip, probe)) {
        ArgusTcpView tcp;

        if (!argus_parse_tcp(ip, &tcp) ||
            tcp.source_port != probe->destination_port ||
            tcp.destination_port != probe->source_port) {
            return false;
        }
        if (type == ARGUS_SCAN_SYN) {
            if ((tcp.flags & (ARGUS_TCP_SYN | ARGUS_TCP_ACK)) ==
                    (ARGUS_TCP_SYN | ARGUS_TCP_ACK) &&
                tcp.acknowledgment == probe->sequence + 1U) {
                classification->state = ARGUS_PORT_OPEN;
                classification->has_fingerprint = argus_fingerprint_from_syn_ack(
                    ip,
                    &tcp,
                    &classification->fingerprint
                );
                return true;
            }
            if ((tcp.flags & ARGUS_TCP_RST) != 0U &&
                (((tcp.flags & ARGUS_TCP_ACK) == 0U) ||
                 tcp.acknowledgment == probe->sequence + 1U)) {
                classification->state = ARGUS_PORT_CLOSED;
                return true;
            }
            return false;
        }
        if ((tcp.flags & ARGUS_TCP_RST) == 0U) {
            return false;
        }
        if (type == ARGUS_SCAN_ACK) {
            classification->state = ARGUS_PORT_UNFILTERED;
        } else if (type == ARGUS_SCAN_WINDOW) {
            classification->state = tcp.window == 0U
                ? ARGUS_PORT_CLOSED
                : ARGUS_PORT_OPEN;
        } else {
            classification->state = ARGUS_PORT_CLOSED;
        }
        return true;
    }

    if (ip->protocol == 1U) {
        ArgusIcmpView icmp;

        if (argus_parse_icmp(ip, &icmp) &&
            (icmp.code == 3U || prohibitive_icmp_code(icmp.code)) &&
            icmp_embeds_probe(&icmp, probe, 6U)) {
            classification->state = ARGUS_PORT_FILTERED;
            return true;
        }
    }
    return false;
}

bool argus_classify_udp_response(
    const ArgusIPv4View *ip,
    const ArgusProbeIdentity *probe,
    ArgusResponseClassification *classification
)
{
    if (ip == NULL || probe == NULL || classification == NULL) {
        return false;
    }
    memset(classification, 0, sizeof(*classification));
    if (ip->more_fragments || ip->fragment_offset != 0U) {
        return false;
    }

    if (ip->protocol == 17U && response_addresses_match(ip, probe)) {
        ArgusUdpView udp;

        if (argus_parse_udp(ip, &udp) &&
            udp.source_port == probe->destination_port &&
            udp.destination_port == probe->source_port) {
            classification->state = ARGUS_PORT_OPEN;
            return true;
        }
        return false;
    }

    if (ip->protocol == 1U) {
        ArgusIcmpView icmp;

        if (!argus_parse_icmp(ip, &icmp) ||
            !icmp_embeds_probe(&icmp, probe, 17U)) {
            return false;
        }
        if (icmp.code == 3U) {
            classification->state = ARGUS_PORT_CLOSED;
            return true;
        }
        if (prohibitive_icmp_code(icmp.code)) {
            classification->state = ARGUS_PORT_FILTERED;
            return true;
        }
    }
    return false;
}
