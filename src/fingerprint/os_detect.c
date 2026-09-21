#include "fingerprint/os_detect.h"

#include "net/packet_builder.h"

#include <stdio.h>
#include <string.h>

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
    return argus_parse_tcp_options(tcp, &fingerprint->tcp_options);
}

ArgusOsGuess argus_os_guess(const ArgusFingerprint *fingerprint)
{
    ArgusOsGuess guess;
    double linux_score = 0.0;
    double windows_score = 0.0;
    double bsd_score = 0.0;

    guess.name = "unknown TCP/IP stack";
    guess.confidence = 0.0;
    guess.evidence[0] = '\0';
    if (fingerprint == NULL) {
        return guess;
    }

    if (fingerprint->estimated_initial_ttl == 64U) {
        linux_score += 0.25;
        bsd_score += 0.25;
    } else if (fingerprint->estimated_initial_ttl == 128U) {
        windows_score += 0.35;
    }

    if (fingerprint->window_size == 29200U || fingerprint->window_size == 64240U) {
        linux_score += 0.30;
    }
    if (fingerprint->window_size == 8192U) {
        windows_score += 0.30;
    }
    if (fingerprint->window_size == 65535U) {
        bsd_score += 0.30;
        windows_score += 0.10;
    }

    if (fingerprint->tcp_options.has_mss) {
        linux_score += 0.05;
        windows_score += 0.05;
        bsd_score += 0.05;
    }
    if (fingerprint->tcp_options.has_sack_permitted) {
        linux_score += 0.10;
        windows_score += 0.10;
        bsd_score += 0.10;
    }
    if (fingerprint->tcp_options.has_timestamps) {
        linux_score += 0.10;
        bsd_score += 0.10;
    }
    if (fingerprint->dont_fragment) {
        linux_score += 0.05;
        windows_score += 0.05;
        bsd_score += 0.05;
    }

    if (linux_score >= windows_score && linux_score >= bsd_score) {
        guess.name = "Linux-like TCP/IP stack";
        guess.confidence = linux_score;
    } else if (windows_score >= bsd_score) {
        guess.name = "Windows-like TCP/IP stack";
        guess.confidence = windows_score;
    } else {
        guess.name = "BSD/macOS-like TCP/IP stack";
        guess.confidence = bsd_score;
    }

    if (guess.confidence > 0.95) {
        guess.confidence = 0.95;
    }
    (void)snprintf(
        guess.evidence,
        sizeof(guess.evidence),
        "observed_ttl=%u,estimated_ttl=%u,window=%u,df=%s,mss=%s,sack=%s,ts=%s,ws=%s",
        (unsigned int)fingerprint->observed_ttl,
        (unsigned int)fingerprint->estimated_initial_ttl,
        (unsigned int)fingerprint->window_size,
        fingerprint->dont_fragment ? "true" : "false",
        fingerprint->tcp_options.has_mss ? "yes" : "no",
        fingerprint->tcp_options.has_sack_permitted ? "yes" : "no",
        fingerprint->tcp_options.has_timestamps ? "yes" : "no",
        fingerprint->tcp_options.has_window_scale ? "yes" : "no"
    );
    return guess;
}

