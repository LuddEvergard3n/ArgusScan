#include "scan/tcp_connect.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static int elapsed_ms(const struct timespec *start, const struct timespec *end)
{
    int64_t seconds = (int64_t)end->tv_sec - (int64_t)start->tv_sec;
    int64_t nanoseconds = (int64_t)end->tv_nsec - (int64_t)start->tv_nsec;
    int64_t total = seconds * 1000 + nanoseconds / 1000000;

    if (total < 0) {
        return 0;
    }
    if (total > INT_MAX) {
        return INT_MAX;
    }
    return (int)total;
}

static ArgusPortState state_from_error(int error_code)
{
    if (error_code == ECONNREFUSED) {
        return ARGUS_PORT_CLOSED;
    }

    return ARGUS_PORT_FILTERED;
}

bool argus_tcp_connect_ipv4(
    struct in_addr address,
    uint16_t port,
    int timeout_ms,
    ArgusConnectResult *result
)
{
    struct sockaddr_in destination;
    struct pollfd descriptor;
    struct timespec start;
    struct timespec end;
    socklen_t error_length;
    int socket_flags;
    int socket_error = 0;
    int connection;
    int poll_status;
    int handle;

    if (port == 0U || timeout_ms <= 0 || result == NULL) {
        return false;
    }

    result->port = port;
    result->state = ARGUS_PORT_FILTERED;
    result->latency_ms = 0;
    result->system_error = 0;

    handle = socket(AF_INET, SOCK_STREAM, 0);
    if (handle < 0) {
        result->system_error = errno;
        return false;
    }

    socket_flags = fcntl(handle, F_GETFL, 0);
    if (socket_flags < 0 || fcntl(handle, F_SETFL, socket_flags | O_NONBLOCK) < 0) {
        result->system_error = errno;
        (void)close(handle);
        return false;
    }

    memset(&destination, 0, sizeof(destination));
    destination.sin_family = AF_INET;
    destination.sin_addr = address;
    destination.sin_port = htons(port);

    (void)clock_gettime(CLOCK_MONOTONIC, &start);
    connection = connect(handle, (const struct sockaddr *)&destination, sizeof(destination));
    if (connection == 0) {
        result->state = ARGUS_PORT_OPEN;
    } else if (errno != EINPROGRESS) {
        socket_error = errno;
        result->state = state_from_error(socket_error);
    } else {
        descriptor.fd = handle;
        descriptor.events = POLLOUT;
        descriptor.revents = 0;
        poll_status = poll(&descriptor, 1U, timeout_ms);
        if (poll_status == 0) {
            socket_error = ETIMEDOUT;
            result->state = ARGUS_PORT_FILTERED;
        } else if (poll_status < 0) {
            socket_error = errno;
            result->state = ARGUS_PORT_FILTERED;
        } else {
            error_length = sizeof(socket_error);
            if (getsockopt(handle, SOL_SOCKET, SO_ERROR, &socket_error, &error_length) != 0) {
                socket_error = errno;
                result->state = ARGUS_PORT_FILTERED;
            } else if (socket_error == 0) {
                result->state = ARGUS_PORT_OPEN;
            } else {
                result->state = state_from_error(socket_error);
            }
        }
    }

    (void)clock_gettime(CLOCK_MONOTONIC, &end);
    result->latency_ms = elapsed_ms(&start, &end);
    result->system_error = socket_error;
    (void)close(handle);
    return true;
}

