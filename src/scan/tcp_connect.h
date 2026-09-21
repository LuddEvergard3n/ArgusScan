#ifndef ARGUS_SCAN_TCP_CONNECT_H
#define ARGUS_SCAN_TCP_CONNECT_H

#include "engine/port_state.h"

#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>

typedef struct {
    uint16_t port;
    ArgusPortState state;
    int latency_ms;
    int system_error;
} ArgusConnectResult;

bool argus_tcp_connect_ipv4(
    struct in_addr address,
    uint16_t port,
    int timeout_ms,
    ArgusConnectResult *result
);

#endif

