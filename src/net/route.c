#include "net/route.h"

#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

bool argus_route_source_ipv4(struct in_addr destination, struct in_addr *source)
{
    struct sockaddr_in remote;
    struct sockaddr_in local;
    socklen_t local_length = sizeof(local);
    int handle;

    if (source == NULL) {
        return false;
    }

    handle = socket(AF_INET, SOCK_DGRAM, 0);
    if (handle < 0) {
        return false;
    }

    memset(&remote, 0, sizeof(remote));
    remote.sin_family = AF_INET;
    remote.sin_addr = destination;
    remote.sin_port = htons(53U);
    if (connect(handle, (const struct sockaddr *)&remote, sizeof(remote)) != 0 ||
        getsockname(handle, (struct sockaddr *)&local, &local_length) != 0) {
        (void)close(handle);
        return false;
    }

    *source = local.sin_addr;
    (void)close(handle);
    return true;
}

