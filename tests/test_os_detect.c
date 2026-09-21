#include "test.h"

#include "fingerprint/os_detect.h"

#include <string.h>

void test_os_detect(void)
{
    static const uint8_t linux_order[] = {2U, 4U, 8U, 1U, 3U};
    static const uint8_t windows_order[] = {2U, 1U, 3U, 1U, 1U, 4U};
    ArgusFingerprint fingerprint;
    ArgusOsGuess guess;

    memset(&fingerprint, 0, sizeof(fingerprint));
    fingerprint.estimated_initial_ttl = 64U;
    fingerprint.window_size = 64240U;
    fingerprint.dont_fragment = true;
    fingerprint.tcp_options.has_sack_permitted = true;
    fingerprint.tcp_options.has_timestamps = true;
    fingerprint.tcp_options.has_window_scale = true;
    memcpy(fingerprint.tcp_options.order, linux_order, sizeof(linux_order));
    fingerprint.tcp_options.order_count = sizeof(linux_order);
    guess = argus_os_guess(&fingerprint);
    ARGUS_CHECK(strcmp(guess.name, "Linux-like TCP/IP stack") == 0);
    ARGUS_CHECK(strcmp(guess.signature_db_version, ARGUS_OS_SIGNATURE_DB_VERSION) == 0);
    ARGUS_CHECK(guess.confidence == 0.82);

    memset(&fingerprint, 0, sizeof(fingerprint));
    fingerprint.estimated_initial_ttl = 128U;
    fingerprint.window_size = 8192U;
    fingerprint.dont_fragment = true;
    fingerprint.tcp_options.has_sack_permitted = true;
    fingerprint.tcp_options.has_window_scale = true;
    memcpy(fingerprint.tcp_options.order, windows_order, sizeof(windows_order));
    fingerprint.tcp_options.order_count = sizeof(windows_order);
    guess = argus_os_guess(&fingerprint);
    ARGUS_CHECK(strcmp(guess.name, "Windows-like TCP/IP stack") == 0);
    ARGUS_CHECK(guess.confidence == 0.82);
}
