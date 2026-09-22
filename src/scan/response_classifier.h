#ifndef ARGUS_SCAN_RESPONSE_CLASSIFIER_H
#define ARGUS_SCAN_RESPONSE_CLASSIFIER_H

#include "engine/port_state.h"
#include "fingerprint/os_detect.h"
#include "net/packet_parser.h"
#include "scan/raw_tcp.h"

#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>

typedef struct {
    struct in_addr source;
    struct in_addr target;
    uint16_t source_port;
    uint16_t destination_port;
    uint32_t sequence;
} ArgusProbeIdentity;

typedef struct {
    ArgusPortState state;
    bool has_fingerprint;
    ArgusFingerprint fingerprint;
} ArgusResponseClassification;

bool argus_classify_tcp_response(
    const ArgusIPv4View *ip,
    const ArgusProbeIdentity *probe,
    ArgusRawTcpScanType type,
    ArgusResponseClassification *classification
);

bool argus_classify_udp_response(
    const ArgusIPv4View *ip,
    const ArgusProbeIdentity *probe,
    ArgusResponseClassification *classification
);

#endif
