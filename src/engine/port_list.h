#ifndef ARGUS_ENGINE_PORT_LIST_H
#define ARGUS_ENGINE_PORT_LIST_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint16_t *ports;
    size_t count;
} ArgusPortList;

bool argus_port_list_parse(const char *text, ArgusPortList *list);
void argus_port_list_destroy(ArgusPortList *list);

#endif

