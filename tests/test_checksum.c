#include "test.h"

#include "net/checksum.h"

#include <stdint.h>

void test_checksum(void)
{
    static const uint8_t ipv4_header[] = {
        0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00,
        0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8, 0x00, 0x01,
        0xc0, 0xa8, 0x00, 0xc7
    };
    static const uint8_t odd_length[] = {0x01, 0x02, 0x03};
    static const uint8_t source[] = {192, 0, 2, 1};
    static const uint8_t destination[] = {198, 51, 100, 2};
    static const uint8_t tcp_header[] = {
        0xc0, 0x00, 0x00, 0x50, 0x01, 0x02, 0x03, 0x04,
        0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0xfa, 0xf0,
        0x00, 0x00, 0x00, 0x00
    };

    ARGUS_CHECK(argus_internet_checksum(ipv4_header, sizeof(ipv4_header)) == 0xb861U);
    ARGUS_CHECK(argus_internet_checksum(odd_length, sizeof(odd_length)) == 0xfbfdU);
    ARGUS_CHECK(argus_internet_checksum(NULL, 0U) == 0xffffU);
    ARGUS_CHECK(argus_internet_checksum(NULL, 1U) == 0U);
    ARGUS_CHECK(
        argus_transport_checksum_ipv4(
            source,
            destination,
            6U,
            tcp_header,
            sizeof(tcp_header)
        ) == 0x0464U
    );
}
