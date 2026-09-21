#ifndef ARGUS_ENGINE_TIMING_H
#define ARGUS_ENGINE_TIMING_H

#include <stdbool.h>

typedef enum {
    ARGUS_TIMING_PARANOID = 0,
    ARGUS_TIMING_SNEAKY = 1,
    ARGUS_TIMING_POLITE = 2,
    ARGUS_TIMING_NORMAL = 3,
    ARGUS_TIMING_AGGRESSIVE = 4,
    ARGUS_TIMING_INSANE = 5
} ArgusTimingTemplate;

typedef struct {
    int initial_rtt_timeout_ms;
    int min_rtt_timeout_ms;
    int max_rtt_timeout_ms;
    int max_retries;
    int scan_delay_ms;
    int max_parallelism;
    int max_outstanding_probes;
    int host_timeout_ms;
    double backoff_multiplier;
} ArgusTimingConfig;

bool argus_timing_config(ArgusTimingTemplate timing, ArgusTimingConfig *config);
const char *argus_timing_name(ArgusTimingTemplate timing);
bool argus_timing_parse(const char *text, ArgusTimingTemplate *timing);

#endif

