#include <netinet/ip.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "packetStructure.h"
#include "ipHeader.h"
#include "utils.h"
#define IP_HEADER_VERSION (4)
#define IP_HEADER_LENGTH (20)
#define CALC_IHL(len) ((len) / 4)
#define CALC_IP_HEADER_LEN(ihl) ((ihl) * 4)
#define CALC_FLAGS(x) (((x) >> 13) & 0x07)
#define CALC_DSCP(x) (((x) >> 2) & 0x3F)
#define CALC_ECTCE(x) ((((x) << 3) & 0x10) | ((x) & 0x01))

int32_t setupIPHeader(const struct ip_header_arg_t *arg, size_t transportLayerSize, struct REF_rawFrame_t *frame) {
    int32_t retVal = (int32_t)IP_HEADER_RETURN_NG;
    struct iphdr ip;
    size_t ipHeaderSize = sizeof(struct iphdr);
    uint8_t *ptr;
    memset(&ip, 0x00, ipHeaderSize);

    if ((NULL != arg) && (NULL != frame)) {
        ip.version = (uint8_t)IP_HEADER_VERSION;
        ip.ihl = (uint8_t)CALC_IHL(IP_HEADER_LENGTH);
        ip.tos = arg->tos;
        ip.tot_len = wrapper_htons(transportLayerSize + ipHeaderSize);
        ip.id = wrapper_htons(arg->id);
        ip.frag_off = wrapper_htons(arg->fragOffset);
        ip.ttl = arg->ttl;
        ip.protocol = arg->protocol;
        ip.check = 0;
        ip.saddr = arg->srcAddr;
        ip.daddr = arg->dstAddr;
        ip.check = ~calcTotal((const uint8_t *)&ip, (int32_t)ipHeaderSize, 0);
        // update raw frame
        ptr = &(frame->buf[frame->length]);
        memcpy(ptr, &ip, ipHeaderSize);
        frame->length += (int32_t)ipHeaderSize;
        retVal = (int32_t)IP_HEADER_RETURN_OK;
    }

    return retVal;
}

int32_t dumpIPHeader(const uint8_t *ptr, struct ip_header_t *ip, size_t *size) {
    int32_t retVal = (int32_t)IP_HEADER_RETURN_NG;
    uint16_t offset;
    const struct iphdr *base;
    char *addr;

    if ((NULL != ptr) && (NULL != ip) && (NULL != size)) {
        base = (const struct iphdr *)ptr;
        offset = wrapper_ntohs(base->frag_off);
        ip->version = base->version;
        ip->headerLength = base->ihl;
        ip->ttl = base->ttl;
        ip->tos = base->tos;
        ip->totalLength = wrapper_ntohs(base->tot_len);
        ip->id = wrapper_ntohs(base->id);
        ip->fragOffset = offset;
        ip->flags = (uint8_t)CALC_FLAGS(offset);
        ip->checksum = wrapper_ntohs(base->check);
        ip->protocol = base->protocol;
        ip->dscp = (uint8_t)CALC_DSCP(base->tos);
        ip->ECT_CE = (uint8_t)CALC_ECTCE(base->tos);
        addr = ip->srcIPAddr;
        wrapper_ip_ntoa(base->saddr, &addr);
        addr = ip->dstIPAddr;
        wrapper_ip_ntoa(base->daddr, &addr);
        (*size) = (size_t)CALC_IP_HEADER_LEN(base->ihl);
        retVal = (int32_t)IP_HEADER_RETURN_OK;
    }

    return retVal;
}
