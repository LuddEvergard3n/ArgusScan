#ifndef ARGUS_SCAN_CONNECT_ENGINE_H
#define ARGUS_SCAN_CONNECT_ENGINE_H

#include "engine/port_list.h"
#include "engine/timing.h"
#include "net/target_resolver.h"
#include "scan/tcp_connect.h"

#include <stdbool.h>

bool argus_tcp_connect_scan(
    const ArgusIPv4Target *target,
    const ArgusPortList *ports,
    const ArgusTimingConfig *timing,
    ArgusConnectResult *results
);

#endif

