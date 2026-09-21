#ifndef ARGUS_NET_ROUTE_H
#define ARGUS_NET_ROUTE_H

#include <netinet/in.h>
#include <stdbool.h>

bool argus_route_source_ipv4(struct in_addr destination, struct in_addr *source);

#endif

