#include "test.h"

#include "net/packet_capture.h"

#include <pcap/pcap.h>
#include <stdint.h>
#include <string.h>

void test_capture_frame(void)
{
    uint8_t ethernet[64];
    uint8_t vlan[64];
    uint8_t sll[64];

    memset(ethernet, 0, sizeof(ethernet));
    ethernet[12] = 0x08U;
    ethernet[13] = 0x00U;
    ethernet[14] = 0x45U;
    ARGUS_CHECK(argus_capture_ipv4_offset(DLT_EN10MB, ethernet, sizeof(ethernet)) == 14);

    memcpy(vlan, ethernet, sizeof(vlan));
    vlan[12] = 0x81U;
    vlan[13] = 0x00U;
    vlan[16] = 0x08U;
    vlan[17] = 0x00U;
    vlan[18] = 0x45U;
    ARGUS_CHECK(argus_capture_ipv4_offset(DLT_EN10MB, vlan, sizeof(vlan)) == 18);

    memset(sll, 0, sizeof(sll));
    sll[14] = 0x08U;
    sll[15] = 0x00U;
    sll[16] = 0x45U;
    ARGUS_CHECK(argus_capture_ipv4_offset(DLT_LINUX_SLL, sll, sizeof(sll)) == 16);

    ARGUS_CHECK(argus_capture_ipv4_offset(DLT_RAW, ethernet, 20U) == 0);
    ARGUS_CHECK(argus_capture_ipv4_offset(DLT_EN10MB, ethernet, 10U) == -1);
    ethernet[12] = 0x86U;
    ethernet[13] = 0xddU;
    ARGUS_CHECK(argus_capture_ipv4_offset(DLT_EN10MB, ethernet, sizeof(ethernet)) == -1);
}

