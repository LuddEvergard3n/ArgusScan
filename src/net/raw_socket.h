#ifndef ARGUS_NET_RAW_SOCKET_H
#define ARGUS_NET_RAW_SOCKET_H

#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    int handle;
    int error_code;
} ArgusRawSocket;

bool argus_raw_socket_open(ArgusRawSocket *socket_state);
bool argus_raw_socket_send(
    ArgusRawSocket *socket_state,
    struct in_addr destination,
    const uint8_t *packet,
    size_t packet_length
);
void argus_raw_socket_close(ArgusRawSocket *socket_state);

#endif

