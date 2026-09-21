#include "engine/port_list.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>

#define ARGUS_PORT_TABLE_SIZE 65536U

static void skip_spaces(const char **cursor)
{
    while (isspace((unsigned char)**cursor) != 0) {
        ++(*cursor);
    }
}

static bool parse_port(const char **cursor, unsigned long *port)
{
    char *end;

    skip_spaces(cursor);
    if (!isdigit((unsigned char)**cursor)) {
        return false;
    }

    errno = 0;
    *port = strtoul(*cursor, &end, 10);
    if (errno != 0 || end == *cursor || *port == 0UL || *port > UINT16_MAX) {
        return false;
    }

    *cursor = end;
    skip_spaces(cursor);
    return true;
}

bool argus_port_list_parse(const char *text, ArgusPortList *list)
{
    bool *selected;
    const char *cursor;
    size_t count = 0U;
    size_t output_index = 0U;
    unsigned long port;

    if (text == NULL || list == NULL || *text == '\0') {
        return false;
    }

    list->ports = NULL;
    list->count = 0U;
    selected = calloc(ARGUS_PORT_TABLE_SIZE, sizeof(*selected));
    if (selected == NULL) {
        return false;
    }

    cursor = text;
    while (*cursor != '\0') {
        unsigned long first;
        unsigned long last;

        if (!parse_port(&cursor, &first)) {
            free(selected);
            return false;
        }
        last = first;

        if (*cursor == '-') {
            ++cursor;
            if (!parse_port(&cursor, &last) || last < first) {
                free(selected);
                return false;
            }
        }

        for (port = first; port <= last; ++port) {
            if (!selected[port]) {
                selected[port] = true;
                ++count;
            }
        }

        if (*cursor == '\0') {
            break;
        }
        if (*cursor != ',') {
            free(selected);
            return false;
        }
        ++cursor;
        skip_spaces(&cursor);
        if (*cursor == '\0') {
            free(selected);
            return false;
        }
    }

    if (count == 0U) {
        free(selected);
        return false;
    }

    list->ports = malloc(count * sizeof(*list->ports));
    if (list->ports == NULL) {
        free(selected);
        return false;
    }

    for (port = 1UL; port <= UINT16_MAX; ++port) {
        if (selected[port]) {
            list->ports[output_index] = (uint16_t)port;
            ++output_index;
        }
    }

    free(selected);
    list->count = count;
    return true;
}

void argus_port_list_destroy(ArgusPortList *list)
{
    if (list == NULL) {
        return;
    }

    free(list->ports);
    list->ports = NULL;
    list->count = 0U;
}
