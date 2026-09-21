#include "net/target_resolver.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <stddef.h>
#include <string.h>

bool argus_resolve_ipv4(const char *name, ArgusIPv4Target *target)
{
    struct addrinfo hints;
    struct addrinfo *addresses = NULL;
    const struct sockaddr_in *address;
    int status;

    if (name == NULL || target == NULL || *name == '\0') {
        return false;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    status = getaddrinfo(name, NULL, &hints, &addresses);
    if (status != 0 || addresses == NULL) {
        if (addresses != NULL) {
            freeaddrinfo(addresses);
        }
        return false;
    }

    address = (const struct sockaddr_in *)addresses->ai_addr;
    target->address = address->sin_addr;
    if (inet_ntop(AF_INET, &target->address, target->numeric, sizeof(target->numeric)) == NULL) {
        freeaddrinfo(addresses);
        return false;
    }

    freeaddrinfo(addresses);
    return true;
}

