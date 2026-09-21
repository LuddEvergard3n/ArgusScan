#ifndef ARGUS_FINGERPRINT_OS_DETECT_H
#define ARGUS_FINGERPRINT_OS_DETECT_H

#include "net/packet_parser.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t observed_ttl;
    uint8_t estimated_initial_ttl;
    uint16_t window_size;
    bool dont_fragment;
    uint16_t ip_id;
    ArgusTcpOptions tcp_options;
} ArgusFingerprint;

typedef struct {
    const char *name;
    double confidence;
    char evidence[256];
} ArgusOsGuess;

bool argus_fingerprint_from_syn_ack(
    const ArgusIPv4View *ip,
    const ArgusTcpView *tcp,
    ArgusFingerprint *fingerprint
);

ArgusOsGuess argus_os_guess(const ArgusFingerprint *fingerprint);

#endif

