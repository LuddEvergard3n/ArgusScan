#include "engine/port_state.h"

const char *argus_port_state_name(ArgusPortState state)
{
    switch (state) {
    case ARGUS_PORT_OPEN:
        return "open";
    case ARGUS_PORT_CLOSED:
        return "closed";
    case ARGUS_PORT_FILTERED:
        return "filtered";
    case ARGUS_PORT_OPEN_FILTERED:
        return "open|filtered";
    case ARGUS_PORT_UNFILTERED:
        return "unfiltered";
    default:
        return "unknown";
    }
}

