#include <stdio.h>
#include <stdint.h>
#include "rawEthernetFrame.h"
#include "packetStructure.h"
#define MAIN_DUMMY_DATA_LENGTH (13)

static void init_data(uint8_t *data, int32_t size) {
    int32_t idx;

    for (idx = 0; idx < size; idx++) {
        data[idx] = (uint8_t)(idx + 1);
    }
}

static int32_t callback(uint8_t packetType, void *data) {
    struct ether_header_t *eth;
    struct ip_header_t *ip;
    struct udp_header_t *udp;
    uint16_t fragmentOffset;
    int32_t idx, len;
    uint8_t *ptr;

    switch (packetType) {
        case REF_ETHER_PACKET:
            eth = (struct ether_header_t *)data;
            printf("=== Ether header ===\n");
            printf("Src Mac Addr: %s\n", eth->srcMacAddr);
            printf("Dst Mac Addr: %s\n", eth->dstMacAddr);
            printf("Ether Type: 0x%04x\n", eth->etherType);
            printf("\n");
            break;

        case REF_IP_PACKET:
            ip = (struct ip_header_t *)data;
            fragmentOffset = (ip->fragOffset) & 0x1FFF;
            printf("=== IP header ===\n");
            printf("Version: %d\n", ip->version);
            printf("Header Length: %d (%d)\n", ip->headerLength, ip->headerLength * 4);
            printf("Type of Service: 0x%02x\n", ip->tos);
            printf("DSCP: 0x%02x\n", ip->dscp);
            printf("ECT: 0x%02x\n", ((ip->ECT_CE) >> 1) & 0x01);
            printf("CE: 0x%02x\n", (ip->ECT_CE) & 0x01);
            printf("Total Length: %u (0x%04x)\n", ip->totalLength, ip->totalLength);
            printf("Identification: 0x%04x\n", ip->id);
            printf("Time to Live: %u (0x%02x)\n", ip->ttl, ip->ttl);
            printf("flags: 0x%02x\n", ip->flags);
            printf("fragmentOffset: 0x%04x\n", fragmentOffset);
            printf("Protocol: 0x%02x\n", ip->protocol);
            printf("Checksum: 0x%04x\n", ip->checksum);
            printf("Src IP Addr: %s\n", ip->srcIPAddr);
            printf("Dst IP Addr: %s\n", ip->dstIPAddr);
            printf("\n");
            break;

        case REF_UDP_PACKET:
            udp = (struct udp_header_t *)data;
            len = (int32_t)udp->dataLength - 8;
            ptr = udp->data;
            printf("=== UDP header ===\n");
            printf("Src Port: %d\n", udp->srcPort);
            printf("Dst Port: %d\n", udp->dstPort);
            printf("Length: %d\n", len);
            printf("Checksum: 0x%04x\n", udp->checksum);
            printf("Data: \n");

            for (idx = 0; idx < len; idx++) {
                printf(" 0x%02x", *ptr);
                ptr++;

                if (0 == ((idx + 1) % 10)) {
                    printf("\n");
                }
            }
            printf("\n");
            break;

        default:
            break;
    }

    return 0;
}

int main(void) {
    int32_t ret;
    struct REF_param_t params;
    struct REF_rawFrame_t *frame = NULL;
    uint8_t dummyData[MAIN_DUMMY_DATA_LENGTH];

    // initialize
    init_data(dummyData, MAIN_DUMMY_DATA_LENGTH);

    // setup ether header
    REF_convertMacAddrAscii2Network("11:22:33:44:55:66", params.ether_header.dstMacAddr);
    REF_convertMacAddrAscii2Network("AA:BB:CC:DD:EE:FF", params.ether_header.srcMacAddr);
    // setup ip header
    params.ip.ttl = 64;
    params.ip.tos = 0x10;
    params.ip.fragOffset = 0x4000;
    params.ip.id = 0x0000;
    params.ip.protocol = REF_USE_UDP;
    REF_convertIPAddrAscii2Network("192.168.1.2", &params.ip.srcAddr);
    REF_convertIPAddrAscii2Network("192.168.1.3", &params.ip.dstAddr);
    // setup udp header
    params.udp.srcPort = 1234;
    params.udp.dstPort = 4567;
    params.udp.dataLength = (uint16_t)MAIN_DUMMY_DATA_LENGTH;
    params.data = dummyData;

    // malloc
    ret = REF_mallocRawFrame(&frame);
    if ((int32_t)REF_SUCCESS != ret) {
        fprintf(stderr, "Error: malloc failed.\n");
        goto EXIT_MAIN;
    }
    // create raw frame
    ret = REF_createRawFrame((const struct REF_param_t *)&params, frame);
    if ((int32_t)REF_SUCCESS != ret) {
        fprintf(stderr, "Error: Failed to create raw frame.\n");
        goto EXIT_MAIN;
    }
    // dump raw frame
    (void)REF_dumpRawFrame((const struct REF_rawFrame_t *)frame, callback);

EXIT_MAIN:
    (void)REF_freeRawFrame(&frame);

    return 0;
}