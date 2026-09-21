#include "test.h"

#include "fingerprint/service_detect.h"

#include <string.h>

void test_service(void)
{
    static const uint8_t ssh[] = "SSH-2.0-OpenSSH_9.6\r\n";
    static const uint8_t http[] = "HTTP/1.1 200 OK\r\n";
    static const uint8_t redis[] = "+PONG\r\n";
    static const uint8_t mysql[] = {0x4aU, 0U, 0U, 0U, 0x0aU, '8', '.', '0'};
    static const uint8_t hostile[] = {'A', '\n', 0x1bU, '\\'};
    char escaped[32];

    ARGUS_CHECK(strcmp(argus_service_match(2222U, ssh, sizeof(ssh) - 1U), "SSH") == 0);
    ARGUS_CHECK(strcmp(argus_service_match(8080U, http, sizeof(http) - 1U), "HTTP") == 0);
    ARGUS_CHECK(strcmp(argus_service_match(6379U, redis, sizeof(redis) - 1U), "Redis") == 0);
    ARGUS_CHECK(strcmp(argus_service_match(3306U, mysql, sizeof(mysql)), "MySQL") == 0);
    ARGUS_CHECK(argus_service_match(1234U, (const uint8_t *)"unknown", 7U) == NULL);

    ARGUS_CHECK(argus_banner_escape(hostile, sizeof(hostile), escaped, sizeof(escaped)) == 9U);
    ARGUS_CHECK(strcmp(escaped, "A\\n\\x1b\\\\") == 0);
}
