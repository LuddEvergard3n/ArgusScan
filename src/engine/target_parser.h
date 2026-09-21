#ifndef ARGUS_ENGINE_TARGET_PARSER_H
#define ARGUS_ENGINE_TARGET_PARSER_H

#include "net/target_resolver.h"

#include <stdbool.h>
#include <stddef.h>

#define ARGUS_MAX_TARGETS 4096U

typedef struct {
    ArgusIPv4Target *targets;
    size_t count;
} ArgusTargetList;

bool argus_target_list_parse(
    const char *text,
    ArgusTargetList *list,
    char *error,
    size_t error_capacity
);

void argus_target_list_destroy(ArgusTargetList *list);

#endif

