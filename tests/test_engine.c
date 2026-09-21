#include "test.h"

#include "engine/port_state.h"
#include "engine/timing.h"

#include <string.h>

void test_engine(void)
{
    ArgusTimingConfig config;
    ArgusTimingTemplate timing;

    ARGUS_CHECK(strcmp(argus_port_state_name(ARGUS_PORT_OPEN), "open") == 0);
    ARGUS_CHECK(strcmp(argus_port_state_name(ARGUS_PORT_OPEN_FILTERED), "open|filtered") == 0);
    ARGUS_CHECK(strcmp(argus_port_state_name((ArgusPortState)99), "unknown") == 0);

    ARGUS_CHECK(argus_timing_parse("normal", &timing));
    ARGUS_CHECK(timing == ARGUS_TIMING_NORMAL);
    ARGUS_CHECK(argus_timing_config(timing, &config));
    ARGUS_CHECK(config.max_parallelism == 64);
    ARGUS_CHECK(config.max_outstanding_probes == 128);
    ARGUS_CHECK(config.max_retries == 2);
    ARGUS_CHECK(strcmp(argus_timing_name(timing), "normal") == 0);

    ARGUS_CHECK(!argus_timing_parse("turbo", &timing));
    ARGUS_CHECK(!argus_timing_config((ArgusTimingTemplate)99, &config));
    ARGUS_CHECK(strcmp(argus_timing_name((ArgusTimingTemplate)99), "unknown") == 0);
}

