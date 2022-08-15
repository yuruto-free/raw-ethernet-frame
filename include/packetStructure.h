#ifndef PACKET_STRUCTURE_H_
#define PACKET_STRUCTURE_H_
#include <stdint.h>
#define REF_ETHER_MACADDR_LENGTH (18)
#define REF_IPADDR_LENGTH (16)

struct ether_header_t {
    char dstMacAddr[REF_ETHER_MACADDR_LENGTH];
    char srcMacAddr[REF_ETHER_MACADDR_LENGTH];
    uint16_t etherType;
    uint16_t padding;
};

struct ip_header_t {
    uint8_t version;
    uint8_t headerLength;
    uint8_t ttl;
    uint8_t tos;
    uint16_t totalLength;
    uint16_t id;
    uint16_t fragOffset;
    uint16_t checksum;
    char srcIPAddr[REF_IPADDR_LENGTH];
    char dstIPAddr[REF_IPADDR_LENGTH];
    uint8_t protocol;
    uint8_t flags;
    uint8_t dscp;
    uint8_t ECT_CE; // ECT: upper 4bit, CE: lower 4bit [ex: 0x10 -> ECT = 1, CE = 0]
};

struct udp_header_t {
    uint16_t srcPort;
    uint16_t dstPort;
    uint16_t segmentLength;
    uint16_t checksum;
    uint16_t dataLength;
    uint16_t padding;
    uint8_t *data;
};

struct tcp_header_t {
    uint16_t srcPort;
    uint16_t dstPort;
    uint32_t seqNum;
    uint32_t ackNum;
    uint8_t dataOffset;
    uint8_t flags;
    uint16_t windowSize;
    uint16_t checksum;
    uint16_t urgentPointer;
    uint16_t optionSize;
    uint16_t dataLength;
    uint8_t *options;
    uint8_t *data;
};

#endif