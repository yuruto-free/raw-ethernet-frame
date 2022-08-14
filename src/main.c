#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "rawEthernetFrame.h"
#include "packetStructure.h"

static void printRawFrame(const struct REF_rawFrame_t *frame) {
    int32_t idx;
    int32_t len;
    uint8_t value;
    (void)REF_getTotalRawFrameLength(frame, &len);

    for (idx = 0; idx < len; idx++) {
        (void)REF_getData(frame, idx, &value);
        printf(" 0x%02x", value);

        if (0 == ((idx + 1) % 10)) {
            printf("\n");
        }
    }
    printf("\n");
}

static void printData(const uint8_t *ptr, int32_t len) {
    int32_t idx;

    for (idx = 0; idx < len; idx++) {
        printf(" 0x%02x", *ptr);
        ptr++;

        if (0 == ((idx + 1) % 10)) {
            printf("\n");
        }
    }
}

static int32_t callback(uint8_t packetType, void *data) {
    struct ether_header_t *eth;
    struct ip_header_t *ip;
    struct udp_header_t *udp;
    struct tcp_header_t *tcp;
    uint16_t fragmentOffset;
    int32_t len;
    uint8_t flags;

    switch (packetType) {
        case REF_ETHER_PACKET:
            eth = (struct ether_header_t *)data;
            printf("===    Ether header   ===\n");
            printf("Src Mac Addr:    %s\n", eth->srcMacAddr);
            printf("Dst Mac Addr:    %s\n", eth->dstMacAddr);
            printf("Ether Type:      0x%04x\n", eth->etherType);
            printf("\n");
            break;

        case REF_IP_PACKET:
            ip = (struct ip_header_t *)data;
            fragmentOffset = (ip->fragOffset) & 0x1FFF;
            printf("===     IP header     ===\n");
            printf("Version:         %d\n", ip->version);
            printf("Header Length:   %d (%d)\n", ip->headerLength, ip->headerLength * 4);
            printf("Type of Service: 0x%02x\n", ip->tos);
            printf("DSCP:            0x%02x\n", ip->dscp);
            printf("ECT:             0x%02x\n", ((ip->ECT_CE) >> 1) & 0x01);
            printf("CE:              0x%02x\n", (ip->ECT_CE) & 0x01);
            printf("Total Length:    0x%04x (%u)\n", ip->totalLength, ip->totalLength);
            printf("Identification:  0x%04x\n", ip->id);
            printf("Time to Live:    0x%02x (%u)\n", ip->ttl, ip->ttl);
            printf("flags:           0x%02x\n", ip->flags);
            printf("fragmentOffset:  0x%04x\n", fragmentOffset);
            printf("Protocol:        0x%02x\n", ip->protocol);
            printf("Checksum:        0x%04x\n", ip->checksum);
            printf("Src IP Addr:     %s\n", ip->srcIPAddr);
            printf("Dst IP Addr:     %s\n", ip->dstIPAddr);
            printf("\n");
            break;

        case REF_UDP_PACKET:
            udp = (struct udp_header_t *)data;
            len = (int32_t)udp->dataLength;
            printf("===     UDP header    ===\n");
            printf("Src Port:        0x%04x (%d)\n", udp->srcPort, udp->srcPort);
            printf("Dst Port:        0x%04x (%d)\n", udp->dstPort, udp->dstPort);
            printf("Segment Length:  0x%04x (%d)\n", udp->segmentLength, udp->segmentLength);
            printf("Data Length:     0x%04x (%d)\n", len, len);
            printf("Checksum:        0x%04x\n", udp->checksum);
            printf("Data: \n");
            printData((const uint8_t *)(udp->data), len);
            printf("\n");
            break;

        case REF_TCP_PACKET:
            tcp = (struct tcp_header_t *)data;
            flags = tcp->flags;
            printf("===     TCP header    ===\n");
            printf("Src Port:        0x%04x (%d)\n", tcp->srcPort, tcp->srcPort);
            printf("Dst Port:        0x%04x (%d)\n", tcp->dstPort, tcp->dstPort);
            printf("Seq Num:         0x%08x\n", tcp->seqNum);
            printf("Ack Num:         0x%08x\n", tcp->ackNum);
            printf("Data Offset:     0x%02x\n", tcp->dataOffset);
            printf("Flags:           0x%02x\n", flags);
            printf(" URG: 0x%02x, ACK: 0x%02x, PSH: 0x%02x\n", REF_GET_TCP_URG(flags), REF_GET_TCP_ACK(flags), REF_GET_TCP_PSH(flags));
            printf(" RST: 0x%02x, SYN: 0x%02x, FIN: 0x%02x\n", REF_GET_TCP_RST(flags), REF_GET_TCP_SYN(flags), REF_GET_TCP_FIN(flags));
            printf("Window Size:     0x%04x\n", tcp->windowSize);
            printf("Checksum:        0x%04x\n", tcp->checksum);
            printf("Urgent Pointer:  0x%04x\n", tcp->urgentPointer);
            printf("Data Length:     0x%04x (%d)\n", tcp->dataLength, tcp->dataLength);
            printf("Option Length:   0x%04x (%d)\n", tcp->optionSize, tcp->optionSize);
            if (NULL != (tcp->options)) {
                printf("Options: \n");
                printData((const uint8_t *)(tcp->options), (int32_t)(tcp->optionSize));
            }
            printf("\n");
            printf("Data: \n");
            printData((const uint8_t *)(tcp->data), (int32_t)(tcp->dataLength));
            printf("\n");
            break;

        default:
            break;
    }

    return 0;
}

static void setupUDP(struct REF_param_t *params) {
    uint8_t dummyData[] = {0x61, 0x62, 0x63};

    // initialize
    memset(params, 0x00, sizeof(struct REF_param_t));

    // setup ether header
    REF_convertMacAddrAscii2Network("11:22:33:44:55:66", params->eth.dstMacAddr);
    REF_convertMacAddrAscii2Network("AA:BB:CC:DD:EE:FF", params->eth.srcMacAddr);

    // setup ip header
    params->ip.ttl = 0x40;
    params->ip.tos = 0x00;
    params->ip.fragOffset = 0x4000;
    params->ip.id = 0x051c;
    REF_convertIPAddrAscii2Network("192.168.0.4", &(params->ip.srcAddr));
    REF_convertIPAddrAscii2Network("192.168.0.3", &(params->ip.dstAddr));
    params->ip.protocol = REF_USE_UDP;

    // setup udp header
    params->udp.srcPort = 0x932c;
    params->udp.dstPort = 0x22ba;
    params->udp.dataLength = (uint16_t)sizeof(dummyData);
    params->data = (const uint8_t *)dummyData;
}

static void setupTCP(struct REF_param_t *params) {
    uint8_t dummyData[] = {0x61, 0x62, 0x63};
    const uint8_t options[] = {
        // No Operation * 2
        0x01, 0x01,
        // TimeStamp
        0x08, 0x0a,
        0x59, 0x22, 0xa4, 0x7c, // timestamp
        0x16, 0x11, 0x21, 0x9b, // echo reply
    };

    // initialize
    memset(params, 0x00, sizeof(struct REF_param_t));

    // setup ether header
    REF_convertMacAddrAscii2Network("11:22:33:44:55:66", params->eth.dstMacAddr);
    REF_convertMacAddrAscii2Network("AA:BB:CC:DD:EE:FF", params->eth.srcMacAddr);

    // setup ip header
    params->ip.ttl = 0x40;
    params->ip.tos = 0x00;
    params->ip.fragOffset = 0x4000;
    params->ip.id = 0x920c;
    REF_convertIPAddrAscii2Network("192.168.0.4", &(params->ip.srcAddr));
    REF_convertIPAddrAscii2Network("192.168.0.3", &(params->ip.dstAddr));
    params->ip.protocol = REF_USE_TCP;

    // setup tcp header
    params->tcp.srcPort = 0xdfe6;
    params->tcp.dstPort = 0x22ba;
    params->tcp.seqNum = 0x5d66c47c;
    params->tcp.ackNum = 0x4fa40985;
    params->tcp.flags = 0x18;
    params->tcp.windowSize = 0x01f6;
    params->tcp.urgentPointer = 0x0000;
    params->tcp.dataLength = (uint16_t)sizeof(dummyData);
    params->tcp.optionLength = (uint16_t)sizeof(options);
    params->tcp.options = options;
    params->data = dummyData;
}

int main(void) {
    int32_t ret;
    struct REF_param_t params;
    struct REF_rawFrame_t *frame = NULL;

    // malloc
    ret = REF_mallocRawFrame(&frame);
    if ((int32_t)REF_SUCCESS != ret) {
        fprintf(stderr, "Error: malloc failed.\n");
        goto EXIT_MAIN;
    }
    // === For UDP ===
    // create raw frame
    memset(&params, 0x00, sizeof(struct REF_param_t));
    setupUDP(&params);
    ret = REF_createRawFrame((const struct REF_param_t *)&params, frame);
    if ((int32_t)REF_SUCCESS != ret) {
        fprintf(stderr, "Error: Failed to create raw frame.\n");
        goto EXIT_MAIN;
    }
    printf("==================================================\n");
    printf("===              Output Raw Frame              ===\n");
    printf("==================================================\n");
    printRawFrame((const struct REF_rawFrame_t *)frame);
    printf("==================================================\n");
    printf("\n");
    // dump raw frame
    printf("==================================================\n");
    printf("===              Check UDP Packet              ===\n");
    printf("==================================================\n");
    (void)REF_dumpRawFrame((const struct REF_rawFrame_t *)frame, callback);
    printf("==================================================\n");
    printf("\n");

    // === For TCP ===
    // create raw frame
    memset(&params, 0x00, sizeof(struct REF_param_t));
    setupTCP(&params);
    ret = REF_createRawFrame((const struct REF_param_t *)&params, frame);
    if ((int32_t)REF_SUCCESS != ret) {
        fprintf(stderr, "Error: Failed to create raw frame.\n");
        goto EXIT_MAIN;
    }
    printf("==================================================\n");
    printf("===              Output Raw Frame              ===\n");
    printf("==================================================\n");
    printRawFrame((const struct REF_rawFrame_t *)frame);
    printf("==================================================\n");
    printf("\n");
    // dump raw frame
    printf("==================================================\n");
    printf("===              Check TCP Packet              ===\n");
    printf("==================================================\n");
    (void)REF_dumpRawFrame((const struct REF_rawFrame_t *)frame, callback);
    printf("==================================================\n");
    printf("\n");

EXIT_MAIN:
    (void)REF_freeRawFrame(&frame);

    return 0;
}
