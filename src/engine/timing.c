#include "engine/timing.h"

#include <string.h>

static const ArgusTimingConfig ARGUS_TIMINGS[] = {
    {300000, 100, 300000, 2, 300000, 1, 1, 0, 1.5},
    {15000, 100, 30000, 2, 15000, 1, 1, 0, 1.5},
    {3000, 100, 10000, 2, 400, 4, 8, 0, 1.5},
    {1000, 100, 5000, 2, 0, 64, 128, 900000, 1.5},
    {500, 50, 1250, 1, 0, 256, 512, 300000, 1.25},
    {100, 25, 300, 0, 0, 1024, 2048, 120000, 1.0}
};

static const char *const ARGUS_TIMING_NAMES[] = {
    "paranoid",
    "sneaky",
    "polite",
    "normal",
    "aggressive",
    "insane"
};

bool argus_timing_config(ArgusTimingTemplate timing, ArgusTimingConfig *config)
{
    if (config == NULL || timing < ARGUS_TIMING_PARANOID || timing > ARGUS_TIMING_INSANE) {
        return false;
    }

    *config = ARGUS_TIMINGS[(int)timing];
    return true;
}

const char *argus_timing_name(ArgusTimingTemplate timing)
{
    if (timing < ARGUS_TIMING_PARANOID || timing > ARGUS_TIMING_INSANE) {
        return "unknown";
    }

    return ARGUS_TIMING_NAMES[(int)timing];
}

bool argus_timing_parse(const char *text, ArgusTimingTemplate *timing)
{
    int index;

    if (text == NULL || timing == NULL) {
        return false;
    }

    for (index = 0; index <= (int)ARGUS_TIMING_INSANE; ++index) {
        if (strcmp(text, ARGUS_TIMING_NAMES[index]) == 0) {
            *timing = (ArgusTimingTemplate)index;
            return true;
        }
    }

    return false;
}

