#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <netinet/in.h>
#include <signal.h>
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
    int reuse = 1;
    int listener;

    if (argc != 2 || parse_port(argv[1], &port) != 0) {
        fprintf(stderr, "usage: %s PORT\n", argv[0]);
        return 2;
    }

    listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0 ||
        setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) != 0) {
        perror("listener setup");
        return 1;
    }

    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(port);
    if (bind(listener, (const struct sockaddr *)&address, sizeof(address)) != 0 ||
        listen(listener, 8) != 0) {
        perror("listener bind");
        (void)close(listener);
        return 1;
    }

    printf("listening on 127.0.0.1:%u\n", (unsigned int)port);
    (void)fflush(stdout);
    for (;;) {
        static const char banner[] = "SSH-2.0-ArgusScanFixture\r\n";
        int client = accept(listener, NULL, NULL);

        if (client < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("listener accept");
            (void)close(listener);
            return 1;
        }
        (void)send(client, banner, sizeof(banner) - 1U, 0);
        (void)close(client);
    }
}
