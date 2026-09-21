#ifndef ARGUS_NET_PACKET_CAPTURE_H
#define ARGUS_NET_PACKET_CAPTURE_H

#include <netinet/in.h>
#include <pcap/pcap.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
    ARGUS_CAPTURE_ERROR = -1,
    ARGUS_CAPTURE_TIMEOUT = 0,
    ARGUS_CAPTURE_PACKET = 1
} ArgusCaptureStatus;

typedef struct {
    pcap_t *handle;
    int datalink;
    int selectable_fd;
    char device[128];
    char error[PCAP_ERRBUF_SIZE];
} ArgusPacketCapture;

int argus_capture_ipv4_offset(int datalink, const uint8_t *frame, size_t frame_length);

int argus_packet_capture_open(
    ArgusPacketCapture *capture,
    struct in_addr source,
    struct in_addr target
);

ArgusCaptureStatus argus_packet_capture_next_ipv4(
    ArgusPacketCapture *capture,
    int timeout_ms,
    const uint8_t **packet,
    size_t *packet_length
);

void argus_packet_capture_close(ArgusPacketCapture *capture);

#endif

