#include "fingerprint/service_detect.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static const uint8_t HTTP_PROBE[] = "HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n";
static const uint8_t REDIS_PROBE[] = "PING\r\n";
static const uint8_t SSH_PREFIX[] = "SSH-";
static const uint8_t HTTP_PREFIX[] = "HTTP/";
static const uint8_t REDIS_PREFIX[] = "+PONG";

static const ArgusServiceProbe SERVICE_PROBES[] = {
    {22U, NULL, 0U, SSH_PREFIX, sizeof(SSH_PREFIX) - 1U, "SSH", true},
    {80U, HTTP_PROBE, sizeof(HTTP_PROBE) - 1U, HTTP_PREFIX, sizeof(HTTP_PREFIX) - 1U, "HTTP", true},
    {8000U, HTTP_PROBE, sizeof(HTTP_PROBE) - 1U, HTTP_PREFIX, sizeof(HTTP_PREFIX) - 1U, "HTTP", true},
    {8080U, HTTP_PROBE, sizeof(HTTP_PROBE) - 1U, HTTP_PREFIX, sizeof(HTTP_PREFIX) - 1U, "HTTP", true},
    {3306U, NULL, 0U, NULL, 0U, "MySQL", true},
    {6379U, REDIS_PROBE, sizeof(REDIS_PROBE) - 1U, REDIS_PREFIX, sizeof(REDIS_PREFIX) - 1U, "Redis", true}
};

static const ArgusServiceProbe *probe_for_port(uint16_t port)
{
    size_t index;

    for (index = 0U; index < sizeof(SERVICE_PROBES) / sizeof(SERVICE_PROBES[0]); ++index) {
        if (SERVICE_PROBES[index].port == port) {
            return &SERVICE_PROBES[index];
        }
    }
    return NULL;
}

static bool starts_with(
    const uint8_t *response,
    size_t response_length,
    const uint8_t *prefix,
    size_t prefix_length
)
{
    return response_length >= prefix_length &&
           memcmp(response, prefix, prefix_length) == 0;
}

const char *argus_service_match(
    uint16_t port,
    const uint8_t *response,
    size_t response_length
)
{
    if (response == NULL || response_length == 0U) {
        return NULL;
    }
    if (starts_with(response, response_length, SSH_PREFIX, sizeof(SSH_PREFIX) - 1U)) {
        return "SSH";
    }
    if (starts_with(response, response_length, HTTP_PREFIX, sizeof(HTTP_PREFIX) - 1U)) {
        return "HTTP";
    }
    if (starts_with(response, response_length, REDIS_PREFIX, sizeof(REDIS_PREFIX) - 1U)) {
        return "Redis";
    }
    if (response_length >= 5U && response[4] == 0x0aU) {
        return "MySQL";
    }
    if (response_length >= 3U && memcmp(response, "220", 3U) == 0) {
        if (port == 21U) {
            return "FTP";
        }
        if (port == 25U || port == 465U || port == 587U) {
            return "SMTP";
        }
    }
    return NULL;
}

size_t argus_banner_escape(
    const uint8_t *banner,
    size_t banner_length,
    char *output,
    size_t output_capacity
)
{
    size_t input_index;
    size_t output_index = 0U;

    if (output == NULL || output_capacity == 0U) {
        return 0U;
    }
    if (banner == NULL && banner_length != 0U) {
        output[0] = '\0';
        return 0U;
    }

    for (input_index = 0U; input_index < banner_length; ++input_index) {
        uint8_t byte = banner[input_index];
        char encoded[5];
        const char *text = encoded;
        size_t text_length;

        if (byte == '\r') {
            text = "\\r";
            text_length = 2U;
        } else if (byte == '\n') {
            text = "\\n";
            text_length = 2U;
        } else if (byte == '\t') {
            text = "\\t";
            text_length = 2U;
        } else if (byte == '\\') {
            text = "\\\\";
            text_length = 2U;
        } else if (byte >= 0x20U && byte <= 0x7eU) {
            encoded[0] = (char)byte;
            text_length = 1U;
        } else {
            (void)snprintf(encoded, sizeof(encoded), "\\x%02x", (unsigned int)byte);
            text_length = 4U;
        }

        if (output_index + text_length >= output_capacity) {
            break;
        }
        memcpy(&output[output_index], text, text_length);
        output_index += text_length;
    }
    output[output_index] = '\0';
    return output_index;
}

static int wait_socket(int handle, short events, int timeout_ms)
{
    struct pollfd descriptor;

    descriptor.fd = handle;
    descriptor.events = events;
    descriptor.revents = 0;
    return poll(&descriptor, 1U, timeout_ms);
}

static bool connect_with_timeout(
    struct in_addr address,
    uint16_t port,
    int timeout_ms,
    int *connected_socket
)
{
    struct sockaddr_in destination;
    socklen_t error_length;
    int flags;
    int socket_error = 0;
    int handle;

    handle = socket(AF_INET, SOCK_STREAM, 0);
    if (handle < 0) {
        return false;
    }
    flags = fcntl(handle, F_GETFL, 0);
    if (flags < 0 || fcntl(handle, F_SETFL, flags | O_NONBLOCK) < 0) {
        (void)close(handle);
        return false;
    }

    memset(&destination, 0, sizeof(destination));
    destination.sin_family = AF_INET;
    destination.sin_addr = address;
    destination.sin_port = htons(port);
    if (connect(handle, (const struct sockaddr *)&destination, sizeof(destination)) != 0) {
        if (errno != EINPROGRESS || wait_socket(handle, POLLOUT, timeout_ms) <= 0) {
            (void)close(handle);
            return false;
        }
        error_length = sizeof(socket_error);
        if (getsockopt(handle, SOL_SOCKET, SO_ERROR, &socket_error, &error_length) != 0 ||
            socket_error != 0) {
            (void)close(handle);
            return false;
        }
    }

    *connected_socket = handle;
    return true;
}

static ssize_t receive_banner(int handle, uint8_t *buffer, size_t capacity, int timeout_ms)
{
    if (wait_socket(handle, POLLIN, timeout_ms) <= 0) {
        return 0;
    }
    return recv(handle, buffer, capacity, 0);
}

bool argus_service_detect_ipv4(
    struct in_addr address,
    uint16_t port,
    int timeout_ms,
    ArgusServiceResult *result
)
{
    const ArgusServiceProbe *probe;
    const char *service;
    ssize_t received;
    int handle;

    if (port == 0U || timeout_ms <= 0 || result == NULL) {
        return false;
    }
    memset(result, 0, sizeof(*result));
    if (!connect_with_timeout(address, port, timeout_ms, &handle)) {
        return false;
    }
    result->connected = true;
    probe = probe_for_port(port);

    received = receive_banner(handle, result->banner, sizeof(result->banner), 150);
    if (received <= 0 && probe != NULL && probe->probe != NULL) {
        ssize_t sent = send(handle, probe->probe, probe->probe_length, 0);
        if (sent == (ssize_t)probe->probe_length) {
            received = receive_banner(handle, result->banner, sizeof(result->banner), timeout_ms);
        }
    }

    if (received > 0) {
        result->banner_length = (size_t)received;
        result->banner_truncated = result->banner_length == sizeof(result->banner);
        service = argus_service_match(port, result->banner, result->banner_length);
        if (service != NULL) {
            result->detected = true;
            (void)snprintf(result->service_name, sizeof(result->service_name), "%s", service);
        } else if (probe != NULL && probe->match_prefix != NULL &&
                   starts_with(
                       result->banner,
                       result->banner_length,
                       probe->match_prefix,
                       probe->match_prefix_length
                   )) {
            result->detected = true;
            (void)snprintf(
                result->service_name,
                sizeof(result->service_name),
                "%s",
                probe->service_name
            );
        }
        (void)argus_banner_escape(
            result->banner,
            result->banner_length,
            result->banner_text,
            sizeof(result->banner_text)
        );
    }

    (void)close(handle);
    return true;
}

