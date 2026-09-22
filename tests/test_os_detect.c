#include "test.h"

#include "fingerprint/os_detect.h"
#include "net/packet_builder.h"

#include <string.h>

void test_os_detect(void)
{
    static const uint8_t linux_order[] = {2U, 4U, 8U, 1U, 3U};
    static const uint8_t windows_order[] = {2U, 1U, 3U, 1U, 1U, 4U};
    ArgusFingerprint fingerprint;
    ArgusActiveFingerprint active;
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

    memset(&active, 0, sizeof(active));
    memset(&fingerprint, 0, sizeof(fingerprint));
    fingerprint.estimated_initial_ttl = 64U;
    fingerprint.window_size = 64240U;
    fingerprint.dont_fragment = true;
    fingerprint.ip_id = 100U;
    fingerprint.tcp_flags = ARGUS_TCP_SYN | ARGUS_TCP_ACK;
    fingerprint.tcp_options.has_sack_permitted = true;
    fingerprint.tcp_options.has_timestamps = true;
    fingerprint.tcp_options.timestamp_value = 1000U;
    fingerprint.tcp_options.has_window_scale = true;
    memcpy(fingerprint.tcp_options.order, linux_order, sizeof(linux_order));
    fingerprint.tcp_options.order_count = sizeof(linux_order);
    active.has_standard = true;
    active.standard = fingerprint;
    active.has_minimal = true;
    active.minimal = fingerprint;
    active.minimal.ip_id = 101U;
    active.has_ecn = true;
    active.ecn = fingerprint;
    active.ecn.ip_id = 102U;
    active.ecn.tcp_flags |= ARGUS_TCP_ECE;
    active.ecn.tcp_options.timestamp_value = 1001U;
    active.closed_port_probed = true;
    active.closed_port_rst = true;
    guess = argus_os_guess_active(&active);
    ARGUS_CHECK(strcmp(guess.name, "Linux-like TCP/IP stack") == 0);
    ARGUS_CHECK(guess.confidence == 0.92);
    ARGUS_CHECK(strstr(guess.evidence, "probe_results=4") != NULL);
    ARGUS_CHECK(strstr(guess.evidence, "ipid=incrementing") != NULL);
    ARGUS_CHECK(strstr(guess.evidence, "timestamps=nondecreasing") != NULL);
    ARGUS_CHECK(strstr(guess.evidence, "ecn_ece=true") != NULL);
}
