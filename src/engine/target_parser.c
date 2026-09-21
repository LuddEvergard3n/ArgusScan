#include "engine/target_parser.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool allocate_targets(ArgusTargetList *list, size_t count)
{
    if (count == 0U || count > ARGUS_MAX_TARGETS) {
        return false;
    }
    list->targets = calloc(count, sizeof(*list->targets));
    if (list->targets == NULL) {
        return false;
    }
    list->count = count;
    return true;
}

static void assign_address(ArgusIPv4Target *target, uint32_t host_order)
{
    target->address.s_addr = htonl(host_order);
    (void)inet_ntop(
        AF_INET,
        &target->address,
        target->numeric,
        sizeof(target->numeric)
    );
}

static bool parse_number(const char *text, unsigned long maximum, unsigned long *value)
{
    char *end;

    if (text == NULL || *text == '\0') {
        return false;
    }
    errno = 0;
    *value = strtoul(text, &end, 10);
    return errno == 0 && end != text && *end == '\0' && *value <= maximum;
}

static bool parse_cidr(
    const char *text,
    const char *slash,
    ArgusTargetList *list,
    char *error,
    size_t error_capacity
)
{
    struct in_addr base_address;
    char address_text[INET_ADDRSTRLEN];
    size_t address_length = (size_t)(slash - text);
    unsigned long prefix;
    uint64_t count;
    uint32_t base;
    uint32_t mask;
    size_t index;

    if (address_length == 0U || address_length >= sizeof(address_text) ||
        !parse_number(slash + 1, 32UL, &prefix)) {
        (void)snprintf(error, error_capacity, "invalid IPv4 CIDR expression");
        return false;
    }
    memcpy(address_text, text, address_length);
    address_text[address_length] = '\0';
    if (inet_pton(AF_INET, address_text, &base_address) != 1) {
        (void)snprintf(error, error_capacity, "invalid IPv4 address before CIDR prefix");
        return false;
    }

    count = UINT64_C(1) << (32U - (unsigned int)prefix);
    if (count > ARGUS_MAX_TARGETS) {
        (void)snprintf(
            error,
            error_capacity,
            "CIDR expands to %llu targets; limit is %u",
            (unsigned long long)count,
            ARGUS_MAX_TARGETS
        );
        return false;
    }

    mask = prefix == 0UL ? 0U : UINT32_MAX << (32U - (unsigned int)prefix);
    base = ntohl(base_address.s_addr) & mask;
    if (!allocate_targets(list, (size_t)count)) {
        (void)snprintf(error, error_capacity, "could not allocate CIDR target list");
        return false;
    }
    for (index = 0U; index < list->count; ++index) {
        assign_address(&list->targets[index], base + (uint32_t)index);
    }
    return true;
}

static bool parse_last_octet_range(
    const char *text,
    const char *dash,
    ArgusTargetList *list,
    char *error,
    size_t error_capacity
)
{
    struct in_addr first_address;
    char first_text[INET_ADDRSTRLEN];
    size_t first_length = (size_t)(dash - text);
    unsigned long last_octet;
    uint32_t first;
    uint32_t prefix;
    unsigned int first_octet;
    size_t count;
    size_t index;

    if (first_length == 0U || first_length >= sizeof(first_text) ||
        !parse_number(dash + 1, 255UL, &last_octet)) {
        return false;
    }
    memcpy(first_text, text, first_length);
    first_text[first_length] = '\0';
    if (inet_pton(AF_INET, first_text, &first_address) != 1) {
        return false;
    }

    first = ntohl(first_address.s_addr);
    first_octet = first & 0xffU;
    if (last_octet < first_octet) {
        (void)snprintf(error, error_capacity, "IPv4 range end precedes its start");
        return false;
    }
    count = (size_t)(last_octet - first_octet + 1UL);
    if (!allocate_targets(list, count)) {
        (void)snprintf(error, error_capacity, "could not allocate IPv4 range");
        return false;
    }

    prefix = first & 0xffffff00U;
    for (index = 0U; index < count; ++index) {
        assign_address(&list->targets[index], prefix | (uint32_t)(first_octet + index));
    }
    return true;
}

bool argus_target_list_parse(
    const char *text,
    ArgusTargetList *list,
    char *error,
    size_t error_capacity
)
{
    const char *slash;
    const char *dash;

    if (text == NULL || list == NULL || error == NULL || error_capacity == 0U ||
        *text == '\0') {
        return false;
    }
    list->targets = NULL;
    list->count = 0U;
    error[0] = '\0';

    slash = strchr(text, '/');
    if (slash != NULL) {
        return parse_cidr(text, slash, list, error, error_capacity);
    }

    dash = strrchr(text, '-');
    if (dash != NULL && parse_last_octet_range(text, dash, list, error, error_capacity)) {
        return true;
    }
    if (error[0] != '\0') {
        return false;
    }

    if (!allocate_targets(list, 1U)) {
        (void)snprintf(error, error_capacity, "could not allocate target");
        return false;
    }
    if (!argus_resolve_ipv4(text, &list->targets[0])) {
        argus_target_list_destroy(list);
        (void)snprintf(error, error_capacity, "could not resolve IPv4 target '%s'", text);
        return false;
    }
    return true;
}

void argus_target_list_destroy(ArgusTargetList *list)
{
    if (list == NULL) {
        return;
    }
    free(list->targets);
    list->targets = NULL;
    list->count = 0U;
}

