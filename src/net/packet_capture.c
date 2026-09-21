#include "net/packet_capture.h"

#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static int64_t monotonic_ms(void)
{
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return 0;
    }
    return (int64_t)now.tv_sec * 1000 + (int64_t)now.tv_nsec / 1000000;
}

static bool same_address(const struct sockaddr *address, struct in_addr expected)
{
    const struct sockaddr_in *ipv4;

    if (address == NULL || address->sa_family != AF_INET) {
        return false;
    }
    ipv4 = (const struct sockaddr_in *)address;
    return ipv4->sin_addr.s_addr == expected.s_addr;
}

static bool find_capture_device(
    struct in_addr source,
    char *device,
    size_t device_capacity,
    char *error
)
{
    pcap_if_t *devices = NULL;
    pcap_if_t *candidate;

    if (pcap_findalldevs(&devices, error) != 0) {
        return false;
    }

    for (candidate = devices; candidate != NULL; candidate = candidate->next) {
        pcap_addr_t *address;

        for (address = candidate->addresses; address != NULL; address = address->next) {
            if (same_address(address->addr, source)) {
                (void)snprintf(device, device_capacity, "%s", candidate->name);
                pcap_freealldevs(devices);
                return true;
            }
        }
    }

    pcap_freealldevs(devices);
    (void)snprintf(error, PCAP_ERRBUF_SIZE, "no capture device owns the selected source address");
    return false;
}

int argus_capture_ipv4_offset(int datalink, const uint8_t *frame, size_t frame_length)
{
    uint16_t protocol;

    if (frame == NULL) {
        return -1;
    }

    if (datalink == DLT_RAW) {
        return frame_length >= 20U ? 0 : -1;
    }
    if (datalink == DLT_EN10MB) {
        size_t offset = 14U;

        if (frame_length < offset) {
            return -1;
        }
        protocol = (uint16_t)(((uint16_t)frame[12] << 8U) | frame[13]);
        if (protocol == 0x8100U || protocol == 0x88a8U) {
            if (frame_length < 18U) {
                return -1;
            }
            protocol = (uint16_t)(((uint16_t)frame[16] << 8U) | frame[17]);
            offset = 18U;
        }
        return protocol == 0x0800U && frame_length >= offset + 20U ? (int)offset : -1;
    }
    if (datalink == DLT_LINUX_SLL) {
        if (frame_length < 36U) {
            return -1;
        }
        protocol = (uint16_t)(((uint16_t)frame[14] << 8U) | frame[15]);
        return protocol == 0x0800U ? 16 : -1;
    }
#ifdef DLT_LINUX_SLL2
    if (datalink == DLT_LINUX_SLL2) {
        if (frame_length < 40U) {
            return -1;
        }
        protocol = (uint16_t)(((uint16_t)frame[0] << 8U) | frame[1]);
        return protocol == 0x0800U ? 20 : -1;
    }
#endif
    return -1;
}

int argus_packet_capture_open(
    ArgusPacketCapture *capture,
    struct in_addr source,
    struct in_addr target
)
{
    struct bpf_program filter;
    char source_text[INET_ADDRSTRLEN];
    char target_text[INET_ADDRSTRLEN];
    char filter_text[160];
    int activate_status;

    if (capture == NULL) {
        return -1;
    }

    memset(capture, 0, sizeof(*capture));
    capture->selectable_fd = -1;
    if (inet_ntop(AF_INET, &source, source_text, sizeof(source_text)) == NULL ||
        inet_ntop(AF_INET, &target, target_text, sizeof(target_text)) == NULL ||
        !find_capture_device(
            source,
            capture->device,
            sizeof(capture->device),
            capture->error
        )) {
        return -1;
    }

    capture->handle = pcap_create(capture->device, capture->error);
    if (capture->handle == NULL) {
        return -1;
    }
    if (pcap_set_snaplen(capture->handle, 65535) != 0 ||
        pcap_set_promisc(capture->handle, 0) != 0 ||
        pcap_set_timeout(capture->handle, 50) != 0 ||
        pcap_set_immediate_mode(capture->handle, 1) != 0) {
        (void)snprintf(capture->error, sizeof(capture->error), "%s", pcap_geterr(capture->handle));
        argus_packet_capture_close(capture);
        return -1;
    }

    activate_status = pcap_activate(capture->handle);
    if (activate_status < 0) {
        (void)snprintf(capture->error, sizeof(capture->error), "%s", pcap_geterr(capture->handle));
        argus_packet_capture_close(capture);
        return -1;
    }

    (void)snprintf(
        filter_text,
        sizeof(filter_text),
        "(((tcp or udp) and src host %s and dst host %s) or (icmp and dst host %s))",
        target_text,
        source_text,
        source_text
    );
    if (pcap_compile(capture->handle, &filter, filter_text, 1, PCAP_NETMASK_UNKNOWN) != 0) {
        (void)snprintf(capture->error, sizeof(capture->error), "%s", pcap_geterr(capture->handle));
        argus_packet_capture_close(capture);
        return -1;
    }
    if (pcap_setfilter(capture->handle, &filter) != 0) {
        (void)snprintf(capture->error, sizeof(capture->error), "%s", pcap_geterr(capture->handle));
        pcap_freecode(&filter);
        argus_packet_capture_close(capture);
        return -1;
    }
    pcap_freecode(&filter);

    capture->datalink = pcap_datalink(capture->handle);
    capture->selectable_fd = pcap_get_selectable_fd(capture->handle);
    return 0;
}

ArgusCaptureStatus argus_packet_capture_next_ipv4(
    ArgusPacketCapture *capture,
    int timeout_ms,
    const uint8_t **packet,
    size_t *packet_length
)
{
    int64_t deadline;

    if (capture == NULL || capture->handle == NULL || timeout_ms < 0 ||
        packet == NULL || packet_length == NULL) {
        return ARGUS_CAPTURE_ERROR;
    }

    deadline = monotonic_ms() + timeout_ms;
    for (;;) {
        struct pcap_pkthdr *header = NULL;
        const u_char *frame = NULL;
        int remaining = (int)(deadline - monotonic_ms());
        int status;

        if (remaining <= 0) {
            return ARGUS_CAPTURE_TIMEOUT;
        }

        if (capture->selectable_fd >= 0) {
            struct pollfd descriptor;

            descriptor.fd = capture->selectable_fd;
            descriptor.events = POLLIN;
            descriptor.revents = 0;
            status = poll(&descriptor, 1U, remaining);
            if (status == 0) {
                return ARGUS_CAPTURE_TIMEOUT;
            }
            if (status < 0) {
                if (errno == EINTR) {
                    continue;
                }
                return ARGUS_CAPTURE_ERROR;
            }
        }

        status = pcap_next_ex(capture->handle, &header, &frame);
        if (status == 1) {
            int offset = argus_capture_ipv4_offset(
                capture->datalink,
                frame,
                (size_t)header->caplen
            );
            if (offset >= 0) {
                *packet = frame + offset;
                *packet_length = (size_t)header->caplen - (size_t)offset;
                return ARGUS_CAPTURE_PACKET;
            }
        } else if (status < 0) {
            return ARGUS_CAPTURE_ERROR;
        }
    }
}

void argus_packet_capture_close(ArgusPacketCapture *capture)
{
    if (capture == NULL) {
        return;
    }
    if (capture->handle != NULL) {
        pcap_close(capture->handle);
    }
    capture->handle = NULL;
    capture->selectable_fd = -1;
}
