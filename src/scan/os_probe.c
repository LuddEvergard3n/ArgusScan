#include "scan/os_probe.h"

#include "engine/port_list.h"
#include "scan/raw_tcp.h"

#include <stdio.h>
#include <string.h>

static bool run_single_probe(
    const ArgusIPv4Target *target,
    const ArgusTimingConfig *timing,
    uint16_t port,
    ArgusTcpProbeProfile profile,
    ArgusRawTcpResult *result,
    char *error,
    size_t error_capacity
)
{
    ArgusPortList ports;

    ports.ports = &port;
    ports.count = 1U;
    return argus_raw_tcp_scan_profile(
        target,
        &ports,
        timing,
        ARGUS_SCAN_SYN,
        profile,
        result,
        error,
        error_capacity
    );
}

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
)
{
    ArgusRawTcpResult result;

    if (target == NULL || timing == NULL || open_port == 0U || standard == NULL ||
        fingerprint == NULL || error == NULL || error_capacity == 0U ||
        (has_closed_port && closed_port == 0U)) {
        return false;
    }
    memset(fingerprint, 0, sizeof(*fingerprint));
    fingerprint->has_standard = true;
    fingerprint->standard = *standard;
    error[0] = '\0';

    if (!run_single_probe(
            target,
            timing,
            open_port,
            ARGUS_TCP_PROBE_MINIMAL,
            &result,
            error,
            error_capacity
        )) {
        return false;
    }
    if (result.state == ARGUS_PORT_OPEN && result.has_fingerprint) {
        fingerprint->has_minimal = true;
        fingerprint->minimal = result.fingerprint;
    }

    if (!run_single_probe(
            target,
            timing,
            open_port,
            ARGUS_TCP_PROBE_ECN,
            &result,
            error,
            error_capacity
        )) {
        return false;
    }
    if (result.state == ARGUS_PORT_OPEN && result.has_fingerprint) {
        fingerprint->has_ecn = true;
        fingerprint->ecn = result.fingerprint;
    }

    if (has_closed_port) {
        if (!run_single_probe(
                target,
                timing,
                closed_port,
                ARGUS_TCP_PROBE_STANDARD,
                &result,
                error,
                error_capacity
            )) {
            return false;
        }
        fingerprint->closed_port_probed = true;
        fingerprint->closed_port_rst = result.state == ARGUS_PORT_CLOSED;
    }

    if (!fingerprint->has_minimal && !fingerprint->has_ecn) {
        (void)snprintf(
            error,
            error_capacity,
            "active OS probes received no additional SYN/ACK responses"
        );
        return false;
    }
    return true;
}
