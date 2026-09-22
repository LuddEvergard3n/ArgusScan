#ifndef ARGUS_SCAN_OS_PROBE_H
#define ARGUS_SCAN_OS_PROBE_H

#include "engine/timing.h"
#include "fingerprint/os_detect.h"
#include "net/target_resolver.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

bool argus_active_os_probe(
    const ArgusIPv4Target *target,
    const ArgusTimingConfig *timing,
    uint16_t open_port,
    const ArgusFingerprint *standard,
    bool has_closed_port,
    uint16_t closed_port,
    ArgusActiveFingerprint *fingerprint,
    char *error,
    size_t error_capacity
);

#endif
