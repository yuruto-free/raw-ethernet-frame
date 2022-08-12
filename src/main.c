#include <stdio.h>
#include <stdint.h>
#include "rawEthernetFrame.h"
#include "packetStructure.h"

static int32_t callback(uint8_t packetType, void *data) {
    struct ether_header_t *eth;
    struct ip_header_t *ip;

    switch (packetType) {
        case REF_ETHER_PACKET:
            eth = (struct ether_header_t *)data;
            printf("Src Mac Addr: %s\n", eth->srcMacAddr);
            printf("Dst Mac Addr: %s\n", eth->dstMacAddr);
            printf("Ether Type: 0x%04x\n", eth->etherType);
            printf("\n");
            break;
        case REF_IP_PACKET:
            ip = (struct ip_header_t *)data;
            printf("Version: %d\n", ip->version);
            printf("Header Length: %d (%d)\n", ip->headerLength, ip->headerLength * 4);
            printf("Type of Service: 0x%02x\n", ip->tos);
            printf("Total Length: %u\n", ip->totalLength);
            printf("Identification: %u\n", ip->id);
            printf("Time to Live: %u\n", ip->ttl);
            printf("Protocol: 0x%02x\n", ip->protocol);
            printf("Checksum: 0x%04x\n", ip->checksum);
            printf("Src IP Addr: %s\n", ip->srcIPAddr);
            printf("Dst IP Addr: %s\n", ip->dstIPAddr);
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
    REF_convertMacAddrAscii2Network("11:22:33:44:55:66", params.ether_header.dstMacAddr);
    REF_convertMacAddrAscii2Network("AA:BB:CC:DD:EE:FF", params.ether_header.srcMacAddr);
    params.ip.ttl = 64;
    params.ip.tos = 0x10;
    params.ip.fragOffset = 0x80;
    params.ip.id = 0;
    params.ip.protocol = REF_USE_TCP;
    REF_convertIPAddrAscii2Network("192.168.1.2", &params.ip.srcAddr);
    REF_convertIPAddrAscii2Network("192.168.1.3", &params.ip.dstAddr);

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