#ifndef ARGUS_NET_TARGET_RESOLVER_H
#define ARGUS_NET_TARGET_RESOLVER_H

#include <netinet/in.h>
#include <stdbool.h>

typedef struct {
    struct in_addr address;
    char numeric[INET_ADDRSTRLEN];
} ArgusIPv4Target;

bool argus_resolve_ipv4(const char *name, ArgusIPv4Target *target);

#endif

