#ifndef ARGUS_FINGERPRINT_OS_DETECT_H
#define ARGUS_FINGERPRINT_OS_DETECT_H

#include "net/packet_parser.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ARGUS_OS_SIGNATURE_DB_VERSION "2026.09"

typedef struct {
    uint8_t observed_ttl;
    uint8_t estimated_initial_ttl;
    uint16_t window_size;
    bool dont_fragment;
    uint16_t ip_id;
    uint8_t tcp_flags;
    ArgusTcpOptions tcp_options;
} ArgusFingerprint;

typedef struct {
    bool has_standard;
    ArgusFingerprint standard;
    bool has_minimal;
    ArgusFingerprint minimal;
    bool has_ecn;
    ArgusFingerprint ecn;
    bool closed_port_probed;
    bool closed_port_rst;
} ArgusActiveFingerprint;

typedef struct {
    const char *name;
    const char *signature_db_version;
    double confidence;
    char evidence[256];
} ArgusOsGuess;

bool argus_fingerprint_from_syn_ack(
    const ArgusIPv4View *ip,
    const ArgusTcpView *tcp,
    ArgusFingerprint *fingerprint
);

ArgusOsGuess argus_os_guess(const ArgusFingerprint *fingerprint);
ArgusOsGuess argus_os_guess_active(const ArgusActiveFingerprint *fingerprint);

#endif
