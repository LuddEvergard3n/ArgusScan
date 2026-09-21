#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int parse_port(const char *text, uint16_t *port)
{
    char *end;
    unsigned long value;

    errno = 0;
    value = strtoul(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value == 0UL || value > UINT16_MAX) {
        return -1;
    }
    *port = (uint16_t)value;
    return 0;
}

int main(int argc, char **argv)
{
    struct sockaddr_in address;
    uint16_t port;
    int handle;

    if (argc != 2 || parse_port(argv[1], &port) != 0) {
        fprintf(stderr, "usage: %s PORT\n", argv[0]);
        return 2;
    }

    handle = socket(AF_INET, SOCK_DGRAM, 0);
    if (handle < 0) {
        perror("udp listener setup");
        return 1;
    }
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(port);
    if (bind(handle, (const struct sockaddr *)&address, sizeof(address)) != 0) {
        perror("udp listener bind");
        (void)close(handle);
        return 1;
    }

    printf("UDP listening on 127.0.0.1:%u\n", (unsigned int)port);
    (void)fflush(stdout);
    for (;;) {
        struct sockaddr_in peer;
        socklen_t peer_length = sizeof(peer);
        uint8_t buffer[64];
        static const uint8_t response[] = {'o', 'k'};
        ssize_t received = recvfrom(
            handle,
            buffer,
            sizeof(buffer),
            0,
            (struct sockaddr *)&peer,
            &peer_length
        );

        if (received < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("udp listener receive");
            (void)close(handle);
            return 1;
        }
        if (sendto(
                handle,
                response,
                sizeof(response),
                0,
                (const struct sockaddr *)&peer,
                peer_length
            ) < 0) {
            perror("udp listener send");
            (void)close(handle);
            return 1;
        }
    }
}

