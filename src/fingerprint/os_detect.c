#include "fingerprint/os_detect.h"

#include "net/packet_builder.h"

#include <stdio.h>
#include <string.h>

typedef struct {
    const char *name;
    uint8_t initial_ttl;
    const uint16_t *windows;
    size_t window_count;
    bool dont_fragment;
    bool sack;
    bool timestamps;
    bool window_scale;
    const uint8_t *option_order;
    size_t option_order_count;
} ArgusOsSignature;

static const uint16_t LINUX_WINDOWS[] = {29200U, 64240U, 65160U};
static const uint16_t WINDOWS_WINDOWS[] = {8192U, 65535U, 64240U};
static const uint16_t BSD_WINDOWS[] = {65535U, 65532U};
static const uint8_t LINUX_OPTION_ORDER[] = {2U, 4U, 8U, 1U, 3U};
static const uint8_t WINDOWS_OPTION_ORDER[] = {2U, 1U, 3U, 1U, 1U, 4U};
static const uint8_t BSD_OPTION_ORDER[] = {2U, 1U, 3U, 1U, 1U, 8U, 4U};

static const ArgusOsSignature OS_SIGNATURES[] = {
    {
        "Linux-like TCP/IP stack", 64U, LINUX_WINDOWS,
        sizeof(LINUX_WINDOWS) / sizeof(LINUX_WINDOWS[0]), true, true, true, true,
        LINUX_OPTION_ORDER, sizeof(LINUX_OPTION_ORDER)
    },
    {
        "Windows-like TCP/IP stack", 128U, WINDOWS_WINDOWS,
        sizeof(WINDOWS_WINDOWS) / sizeof(WINDOWS_WINDOWS[0]), true, true, false, true,
        WINDOWS_OPTION_ORDER, sizeof(WINDOWS_OPTION_ORDER)
    },
    {
        "BSD/macOS-like TCP/IP stack", 64U, BSD_WINDOWS,
        sizeof(BSD_WINDOWS) / sizeof(BSD_WINDOWS[0]), true, true, true, true,
        BSD_OPTION_ORDER, sizeof(BSD_OPTION_ORDER)
    }
};

static uint8_t estimate_initial_ttl(uint8_t observed)
{
    if (observed <= 64U) {
        return 64U;
    }
    if (observed <= 128U) {
        return 128U;
    }
    return 255U;
}

bool argus_fingerprint_from_syn_ack(
    const ArgusIPv4View *ip,
    const ArgusTcpView *tcp,
    ArgusFingerprint *fingerprint
)
{
    if (ip == NULL || tcp == NULL || fingerprint == NULL ||
        (tcp->flags & (ARGUS_TCP_SYN | ARGUS_TCP_ACK)) !=
            (ARGUS_TCP_SYN | ARGUS_TCP_ACK)) {
        return false;
    }

    memset(fingerprint, 0, sizeof(*fingerprint));
    fingerprint->observed_ttl = ip->ttl;
    fingerprint->estimated_initial_ttl = estimate_initial_ttl(ip->ttl);
    fingerprint->window_size = tcp->window;
    fingerprint->dont_fragment = ip->dont_fragment;
    fingerprint->ip_id = ip->identification;
    fingerprint->tcp_flags = tcp->flags;
    return argus_parse_tcp_options(tcp, &fingerprint->tcp_options);
}

static bool window_matches(const ArgusOsSignature *signature, uint16_t window)
{
    size_t index;

    for (index = 0U; index < signature->window_count; ++index) {
        if (signature->windows[index] == window) {
            return true;
        }
    }
    return false;
}

static bool option_order_matches(
    const ArgusOsSignature *signature,
    const ArgusTcpOptions *options
)
{
    return options->order_count == signature->option_order_count &&
        memcmp(options->order, signature->option_order, options->order_count) == 0;
}

static double signature_score(
    const ArgusOsSignature *signature,
    const ArgusFingerprint *fingerprint
)
{
    double score = 0.0;

    if (fingerprint->estimated_initial_ttl == signature->initial_ttl) {
        score += 0.30;
    }
    if (window_matches(signature, fingerprint->window_size)) {
        score += 0.25;
    }
    if (fingerprint->dont_fragment == signature->dont_fragment) {
        score += 0.05;
    }
    if (fingerprint->tcp_options.has_sack_permitted == signature->sack) {
        score += 0.10;
    }
    if (fingerprint->tcp_options.has_timestamps == signature->timestamps) {
        score += 0.10;
    }
    if (fingerprint->tcp_options.has_window_scale == signature->window_scale) {
        score += 0.10;
    }
    if (option_order_matches(signature, &fingerprint->tcp_options)) {
        score += 0.10;
    }
    return score;
}

ArgusOsGuess argus_os_guess(const ArgusFingerprint *fingerprint)
{
    ArgusOsGuess guess;
    size_t best_index = 0U;
    size_t index;
    double best_score = 0.0;

    guess.name = "unknown TCP/IP stack";
    guess.signature_db_version = ARGUS_OS_SIGNATURE_DB_VERSION;
    guess.confidence = 0.0;
    guess.evidence[0] = '\0';
    if (fingerprint == NULL) {
        return guess;
    }

    for (index = 0U; index < sizeof(OS_SIGNATURES) / sizeof(OS_SIGNATURES[0]); ++index) {
        double score = signature_score(&OS_SIGNATURES[index], fingerprint);

        if (score > best_score) {
            best_score = score;
            best_index = index;
        }
    }

    if (best_score >= 0.30) {
        guess.name = OS_SIGNATURES[best_index].name;
        guess.confidence = best_score > 0.82 ? 0.82 : best_score;
    }
    (void)snprintf(
        guess.evidence,
        sizeof(guess.evidence),
        "db=%s,observed_ttl=%u,estimated_ttl=%u,window=%u,df=%s,mss=%s,sack=%s,ts=%s,ws=%s,option_count=%zu",
        ARGUS_OS_SIGNATURE_DB_VERSION,
        (unsigned int)fingerprint->observed_ttl,
        (unsigned int)fingerprint->estimated_initial_ttl,
        (unsigned int)fingerprint->window_size,
        fingerprint->dont_fragment ? "true" : "false",
        fingerprint->tcp_options.has_mss ? "yes" : "no",
        fingerprint->tcp_options.has_sack_permitted ? "yes" : "no",
        fingerprint->tcp_options.has_timestamps ? "yes" : "no",
        fingerprint->tcp_options.has_window_scale ? "yes" : "no",
        fingerprint->tcp_options.order_count
    );
    return guess;
}

static const char *ip_id_pattern(const ArgusActiveFingerprint *fingerprint)
{
    uint16_t first;
    uint16_t second;
    uint16_t third;
    uint16_t first_delta;
    uint16_t second_delta;

    if (!fingerprint->has_standard || !fingerprint->has_minimal ||
        !fingerprint->has_ecn) {
        return "insufficient";
    }
    first = fingerprint->standard.ip_id;
    second = fingerprint->minimal.ip_id;
    third = fingerprint->ecn.ip_id;
    if (first == 0U && second == 0U && third == 0U) {
        return "zero";
    }
    first_delta = (uint16_t)(second - first);
    second_delta = (uint16_t)(third - second);
    if (first_delta <= 32U && second_delta <= 32U) {
        return "incrementing";
    }
    return "variable";
}

static bool consistent_ttl_df(const ArgusActiveFingerprint *fingerprint)
{
    const ArgusFingerprint *baseline;

    if (!fingerprint->has_standard) {
        return false;
    }
    baseline = &fingerprint->standard;
    if (fingerprint->has_minimal &&
        (fingerprint->minimal.estimated_initial_ttl != baseline->estimated_initial_ttl ||
         fingerprint->minimal.dont_fragment != baseline->dont_fragment)) {
        return false;
    }
    if (fingerprint->has_ecn &&
        (fingerprint->ecn.estimated_initial_ttl != baseline->estimated_initial_ttl ||
         fingerprint->ecn.dont_fragment != baseline->dont_fragment)) {
        return false;
    }
    return true;
}

static const char *timestamp_pattern(const ArgusActiveFingerprint *fingerprint)
{
    if (!fingerprint->has_standard || !fingerprint->has_ecn ||
        !fingerprint->standard.tcp_options.has_timestamps ||
        !fingerprint->ecn.tcp_options.has_timestamps) {
        return "not-observed";
    }
    return fingerprint->ecn.tcp_options.timestamp_value >=
        fingerprint->standard.tcp_options.timestamp_value
        ? "nondecreasing"
        : "nonmonotonic";
}

ArgusOsGuess argus_os_guess_active(const ArgusActiveFingerprint *fingerprint)
{
    ArgusOsGuess guess;
    size_t best_index = 0U;
    size_t index;
    size_t scored_probes = 0U;
    size_t observed_probes = 0U;
    double best_score = 0.0;
    bool ttl_df_consistent;
    bool ecn_echo = false;

    guess.name = "unknown TCP/IP stack";
    guess.signature_db_version = ARGUS_OS_SIGNATURE_DB_VERSION;
    guess.confidence = 0.0;
    guess.evidence[0] = '\0';
    if (fingerprint == NULL || !fingerprint->has_standard) {
        return guess;
    }

    observed_probes = 1U + (fingerprint->has_minimal ? 1U : 0U) +
        (fingerprint->has_ecn ? 1U : 0U) +
        (fingerprint->closed_port_probed ? 1U : 0U);
    for (index = 0U; index < sizeof(OS_SIGNATURES) / sizeof(OS_SIGNATURES[0]); ++index) {
        double score = signature_score(&OS_SIGNATURES[index], &fingerprint->standard);
        size_t count = 1U;

        if (fingerprint->has_ecn) {
            score += signature_score(&OS_SIGNATURES[index], &fingerprint->ecn);
            ++count;
        }
        score /= (double)count;
        if (score > best_score) {
            best_score = score;
            best_index = index;
        }
        scored_probes = count;
    }

    ttl_df_consistent = consistent_ttl_df(fingerprint);
    if (fingerprint->has_ecn) {
        ecn_echo = (fingerprint->ecn.tcp_flags & ARGUS_TCP_ECE) != 0U;
    }

    if (best_score >= 0.30) {
        guess.name = OS_SIGNATURES[best_index].name;
        guess.confidence = best_score;
        if (scored_probes >= 2U && ttl_df_consistent) {
            guess.confidence += 0.05;
        }
        if (fingerprint->closed_port_probed && fingerprint->closed_port_rst) {
            guess.confidence += 0.02;
        }
        if (guess.confidence > 0.92) {
            guess.confidence = 0.92;
        }
    }

    (void)snprintf(
        guess.evidence,
        sizeof(guess.evidence),
        "db=%s,probe_results=%zu,ttl_df_consistent=%s,ipid=%s,timestamps=%s,ecn_ece=%s,closed_rst=%s",
        ARGUS_OS_SIGNATURE_DB_VERSION,
        observed_probes,
        ttl_df_consistent ? "true" : "false",
        ip_id_pattern(fingerprint),
        timestamp_pattern(fingerprint),
        ecn_echo ? "true" : "false",
        fingerprint->closed_port_probed
            ? (fingerprint->closed_port_rst ? "true" : "false")
            : "not-probed"
    );
    return guess;
}
