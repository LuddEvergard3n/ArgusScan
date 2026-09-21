#include "test.h"

#include "scan/tcp_connect.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

void test_connect(void)
{
    struct sockaddr_in loopback;
    struct sockaddr_in bound;
    ArgusConnectResult result;
    socklen_t bound_length = sizeof(bound);
    int listener;

    listener = socket(AF_INET, SOCK_STREAM, 0);
    ARGUS_CHECK(listener >= 0);
    if (listener < 0) {
        return;
    }

    memset(&loopback, 0, sizeof(loopback));
    loopback.sin_family = AF_INET;
    loopback.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    loopback.sin_port = 0;

    if (bind(listener, (const struct sockaddr *)&loopback, sizeof(loopback)) != 0) {
        ARGUS_CHECK(0);
        (void)close(listener);
        return;
    }
    if (listen(listener, 1) != 0) {
        ARGUS_CHECK(0);
        (void)close(listener);
        return;
    }
    if (getsockname(listener, (struct sockaddr *)&bound, &bound_length) != 0) {
        ARGUS_CHECK(0);
        (void)close(listener);
        return;
    }

    ARGUS_CHECK(argus_tcp_connect_ipv4(
        loopback.sin_addr,
        ntohs(bound.sin_port),
        1000,
        &result
    ));
    ARGUS_CHECK(result.state == ARGUS_PORT_OPEN);
    ARGUS_CHECK(result.system_error == 0);

    (void)close(listener);
    ARGUS_CHECK(argus_tcp_connect_ipv4(
        loopback.sin_addr,
        ntohs(bound.sin_port),
        1000,
        &result
    ));
    ARGUS_CHECK(result.state == ARGUS_PORT_CLOSED);

    ARGUS_CHECK(!argus_tcp_connect_ipv4(loopback.sin_addr, 0U, 1000, &result));
}
