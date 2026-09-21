#ifndef ARGUS_SCAN_RAW_TCP_H
#define ARGUS_SCAN_RAW_TCP_H

#include "engine/port_list.h"
#include "engine/port_state.h"
#include "engine/timing.h"
#include "fingerprint/os_detect.h"
#include "net/target_resolver.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
    ARGUS_SCAN_SYN = 0,
    ARGUS_SCAN_FIN = 1,
    ARGUS_SCAN_NULL = 2,
    ARGUS_SCAN_XMAS = 3,
    ARGUS_SCAN_ACK = 4,
    ARGUS_SCAN_WINDOW = 5
} ArgusRawTcpScanType;

typedef struct {
    uint16_t port;
    ArgusPortState state;
    int latency_ms;
    bool has_fingerprint;
    ArgusFingerprint fingerprint;
} ArgusRawTcpResult;

const char *argus_raw_tcp_scan_name(ArgusRawTcpScanType type);
bool argus_raw_tcp_scan_parse(const char *text, ArgusRawTcpScanType *type);

bool argus_raw_tcp_scan(
    const ArgusIPv4Target *target,
    const ArgusPortList *ports,
    const ArgusTimingConfig *timing,
    ArgusRawTcpScanType type,
    ArgusRawTcpResult *results,
    char *error,
    size_t error_capacity
);

#endif

