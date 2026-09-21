#ifndef ARGUS_ENGINE_PORT_STATE_H
#define ARGUS_ENGINE_PORT_STATE_H

typedef enum {
    ARGUS_PORT_OPEN = 0,
    ARGUS_PORT_CLOSED = 1,
    ARGUS_PORT_FILTERED = 2,
    ARGUS_PORT_OPEN_FILTERED = 3,
    ARGUS_PORT_UNFILTERED = 4
} ArgusPortState;

const char *argus_port_state_name(ArgusPortState state);

#endif

