#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "rawFrame.h"
#include "packetStructure.h"
#include "ipHeader.h"
#include "utils.h"
#define IP_HEADER_VERSION (4)
#define IP_HEADER_LENGTH (20)
#define CALC_IHL(len) ((len) / 4)
#define CHECKSUM_MSB (0x80000000)
#define CHECKSUM_MASK (0x0000FFFF)
#define SHIFT_CHECKSUM(x) (((x) & (uint32_t)CHECKSUM_MASK) + (((x) >> 16) & (uint32_t)CHECKSUM_MASK))

/**
 * @brief calculate checksum of ip header
 * 
 * @param data   target data
 * @param length data length
 * @return checksum
 */
uint16_t calcChksum(const uint8_t *data, int32_t length);

int32_t setupIPHeader(const struct ip_header_arg_t *arg, struct REF_rawFrame_t *frame) {
    int32_t retVal = (int32_t)IP_HEADER_RETURN_NG;
    struct iphdr ip;
    uint8_t transportProtocol;
    size_t transportLayerSize = 0;
    size_t ipHeaderSize = sizeof(struct iphdr);
    memset(&ip, 0x00, ipHeaderSize);

    if ((NULL != arg) && (NULL != frame)) {
        switch (arg->protocol) {
            case REF_USE_TCP:
                transportLayerSize = sizeof(struct tcphdr);
                transportProtocol = IPPROTO_TCP;
                break;
            case REF_USE_UDP:
                transportLayerSize = sizeof(struct udphdr);
                transportProtocol = IPPROTO_UDP;
                break;
            default:
                break;
        }
        if (0 == transportLayerSize) {
            goto EXIT_IP_HEADER;
        }

        ip.version = IP_HEADER_VERSION;
        ip.ihl = CALC_IHL(IP_HEADER_LENGTH);
        ip.tos = arg->tos;
        ip.tot_len = wrapper_htos(transportLayerSize + ipHeaderSize);
        ip.id = arg->id;
        ip.frag_off = arg->fragOffset;
        ip.ttl = arg->ttl;
        ip.protocol = transportProtocol;
        ip.check = 0;
        ip.saddr = arg->srcAddr;
        ip.daddr = arg->dstAddr;
        ip.check = calcChksum((const uint8_t *)&ip, ipHeaderSize);
        memcpy(&frame->buf[frame->length], &ip, ipHeaderSize);
        frame->length += ipHeaderSize;

        retVal = (int32_t)IP_HEADER_RETURN_OK;
    }

EXIT_IP_HEADER: 
    return retVal;
}

int32_t dumpIPHeader(const uint8_t *ptr, struct ip_header_t *ip, size_t *size) {
    int32_t retVal = (int32_t)IP_HEADER_RETURN_NG;
    struct iphdr *base;
    char *addr;

    if ((NULL != ptr) && (NULL != ip) && (NULL != size)) {
        base = (struct iphdr *)ptr;
        ip->version = base->version;
        ip->headerLength = base->ihl;
        ip->ttl = base->ttl;
        ip->tos = base->tos;
        ip->totalLength = wrapper_ntohs(base->tot_len);
        ip->id = base->id;
        ip->fragOffset = base->frag_off;
        ip->checksum = base->check;
        ip->protocol = base->protocol;
        addr = ip->srcIPAddr;
        wrapper_ip_ntoa(base->saddr, &addr);
        addr = ip->dstIPAddr;
        wrapper_ip_ntoa(base->daddr, &addr);
        (*size) = sizeof(struct iphdr);

        retVal = (int32_t)IP_HEADER_RETURN_OK;
    }

    return retVal;
}

uint16_t calcChksum(const uint8_t *data, int32_t length) {
    register uint32_t sum;
    register const uint16_t *ptr;
    register int32_t idx;
    uint16_t val;

    sum = 0;
    ptr = (const uint16_t *)data;

    for (idx = length; idx > 1; idx -= 2) {
        sum += (*ptr);
        // check overflow
        if (sum & (uint32_t)CHECKSUM_MSB) {
            sum = SHIFT_CHECKSUM(sum);
        }
        ptr++;
    }
    if (1 == idx) {
        val = 0;
        memcpy(&val, ptr, sizeof(uint8_t));
        sum += (val & 0x00FF);
    }
    while (sum >> 16) {
        sum = SHIFT_CHECKSUM(sum);
    }

    return (~sum);
}