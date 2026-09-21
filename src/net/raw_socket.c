#include "net/raw_socket.h"

#include <errno.h>
#include <limits.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

bool argus_raw_socket_open(ArgusRawSocket *socket_state)
{
    int enabled = 1;

    if (socket_state == NULL) {
        return false;
    }

    socket_state->handle = -1;
    socket_state->error_code = 0;
    socket_state->handle = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (socket_state->handle < 0) {
        socket_state->error_code = errno;
        return false;
    }

    if (setsockopt(
            socket_state->handle,
            IPPROTO_IP,
            IP_HDRINCL,
            &enabled,
            sizeof(enabled)
        ) != 0) {
        socket_state->error_code = errno;
        (void)close(socket_state->handle);
        socket_state->handle = -1;
        return false;
    }

    return true;
}

bool argus_raw_socket_send(
    ArgusRawSocket *socket_state,
    struct in_addr destination,
    const uint8_t *packet,
    size_t packet_length
)
{
    struct sockaddr_in address;
    ssize_t sent;

    if (socket_state == NULL || socket_state->handle < 0 || packet == NULL ||
        packet_length == 0U || packet_length > (size_t)SSIZE_MAX) {
        return false;
    }

    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr = destination;
    sent = sendto(
        socket_state->handle,
        packet,
        packet_length,
        0,
        (const struct sockaddr *)&address,
        sizeof(address)
    );
    if (sent < 0 || (size_t)sent != packet_length) {
        socket_state->error_code = sent < 0 ? errno : EIO;
        return false;
    }

    return true;
}

void argus_raw_socket_close(ArgusRawSocket *socket_state)
{
    if (socket_state == NULL) {
        return;
    }
    if (socket_state->handle >= 0) {
        (void)close(socket_state->handle);
    }
    socket_state->handle = -1;
}

