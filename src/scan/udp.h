#ifndef ARGUS_SCAN_UDP_H
#define ARGUS_SCAN_UDP_H

#include "engine/port_list.h"
#include "engine/port_state.h"
#include "engine/timing.h"
#include "net/target_resolver.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint16_t port;
    ArgusPortState state;
    int latency_ms;
} ArgusUdpResult;

bool argus_udp_scan(
    const ArgusIPv4Target *target,
    const ArgusPortList *ports,
    const ArgusTimingConfig *timing,
    ArgusUdpResult *results,
    char *error,
    size_t error_capacity
);

#endif

