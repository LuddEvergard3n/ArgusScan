#ifndef ARGUS_OUTPUT_REPORT_H
#define ARGUS_OUTPUT_REPORT_H

#include "engine/port_state.h"
#include "fingerprint/os_detect.h"
#include "fingerprint/service_detect.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
    ARGUS_OUTPUT_TEXT = 0,
    ARGUS_OUTPUT_JSON = 1,
    ARGUS_OUTPUT_XML = 2
} ArgusOutputFormat;

typedef struct {
    uint16_t port;
    const char *protocol;
    ArgusPortState state;
    int latency_ms;
    bool has_fingerprint;
    ArgusFingerprint fingerprint;
    bool has_service;
    ArgusServiceResult service;
} ArgusReportPort;

typedef struct {
    const char *target;
    const char *target_ip;
    const char *scan_type;
    const char *timing;
    const char *started_at;
    int64_t duration_ms;
    bool has_active_fingerprint;
    ArgusActiveFingerprint active_fingerprint;
    const ArgusReportPort *ports;
    size_t port_count;
} ArgusScanReport;

bool argus_output_format_parse(const char *text, ArgusOutputFormat *format);
void argus_output_report(const ArgusScanReport *report, ArgusOutputFormat format);

#endif
