#ifndef ARGUS_FINGERPRINT_SERVICE_DETECT_H
#define ARGUS_FINGERPRINT_SERVICE_DETECT_H

#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ARGUS_SERVICE_NAME_CAPACITY 32U
#define ARGUS_BANNER_RAW_CAPACITY 512U
#define ARGUS_BANNER_TEXT_CAPACITY 1024U

typedef struct {
    uint16_t port;
    const uint8_t *probe;
    size_t probe_length;
    const uint8_t *match_prefix;
    size_t match_prefix_length;
    const char *service_name;
    bool passive_first;
} ArgusServiceProbe;

typedef struct {
    bool connected;
    bool detected;
    bool banner_truncated;
    char service_name[ARGUS_SERVICE_NAME_CAPACITY];
    uint8_t banner[ARGUS_BANNER_RAW_CAPACITY];
    size_t banner_length;
    char banner_text[ARGUS_BANNER_TEXT_CAPACITY];
} ArgusServiceResult;

const char *argus_service_match(
    uint16_t port,
    const uint8_t *response,
    size_t response_length
);

size_t argus_banner_escape(
    const uint8_t *banner,
    size_t banner_length,
    char *output,
    size_t output_capacity
);

bool argus_service_detect_ipv4(
    struct in_addr address,
    uint16_t port,
    int timeout_ms,
    ArgusServiceResult *result
);

#endif

