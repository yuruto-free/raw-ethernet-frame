#ifndef PACKET_STRUCTURE_H_
#define PACKET_STRUCTURE_H_
#include <stdint.h>
#define REF_ETHER_MACADDR_LENGTH (18)
#define REF_IPADDR_LENGTH (16)
#define REF_USE_TCP (0x06)
#define REF_USE_UDP (0x11)

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
    uint8_t padding[3];
};

#endif