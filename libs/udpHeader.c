#include <netinet/in.h>
#include <netinet/udp.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "packetStructure.h"
#include "udpHeader.h"
#include "utils.h"

struct pseudo_header_t {
    uint32_t srcIPAddr;
    uint32_t dstIPAddr;
    uint16_t protocol; // reserved(uint8_t) + protocol(uint8_t)
    uint16_t dataLength;
    uint16_t srcPort;
    uint16_t dstPort;
    uint16_t len;
    uint16_t checksum;
};

/**
 * @brief calculate checksum of udp header
 * 
 * @param[in] header     pseudo header
 * @param[in] data       target data
 * @param[in] headerSize pseudo header size
 * @param[in] dataLength data length
 * @return    checksum 
 */
static uint16_t calcChksum(const uint8_t *header, const uint8_t *data, size_t headerSize, uint16_t dataLength);

int32_t setupUdpHeader(const struct udp_header_arg_t *arg, struct REF_rawFrame_t *frame) {
    int32_t retVal = (int32_t)UDP_HEADER_RETURN_NG;
    struct udphdr udp;
    struct pseudo_header_t ph;
    int32_t pos;
    size_t udpHeaderSize;

    if ((NULL != arg) && (NULL != frame)) {
        udpHeaderSize = sizeof(struct udphdr);
        udp.uh_sport = wrapper_htons(arg->srcPort);
        udp.uh_dport = wrapper_htons(arg->dstPort);
        udp.uh_ulen = wrapper_htons(arg->dataLength + udpHeaderSize);
        // setup pseudo header
        ph.srcIPAddr = arg->srcIPAddr;
        ph.dstIPAddr = arg->dstIPAddr;
        ph.protocol = wrapper_htons((uint16_t)IPPROTO_UDP);
        ph.dataLength = udp.uh_ulen;
        ph.srcPort = wrapper_htons(arg->srcPort);
        ph.dstPort = wrapper_htons(arg->dstPort);
        ph.len = udp.uh_ulen;
        ph.checksum = 0;
        udp.uh_sum = calcChksum((const uint8_t *)&ph, (const uint8_t *)(arg->data), sizeof(struct pseudo_header_t), arg->dataLength);
        // update raw frame
        pos = frame->length;
        memcpy(&(frame->buf[pos]), &udp, udpHeaderSize);
        pos = frame->length + (int32_t)udpHeaderSize;
        memcpy(&(frame->buf[pos]), arg->data, arg->dataLength);
        frame->length += ((int32_t)udpHeaderSize + arg->dataLength);
        retVal = (int32_t)UDP_HEADER_RETURN_OK;
    }

    return retVal;
}

int32_t dumpUdpHeader(const uint8_t *ptr, struct udp_header_t *udp, size_t *size) {
    int32_t retVal = (int32_t)UDP_HEADER_RETURN_NG;
    struct udphdr *base;
    size_t udpHeaderSize = sizeof(struct udphdr);

    if ((NULL != ptr) && (NULL != udp) && (NULL != size)) {
        base = (struct udphdr *)ptr;
        udp->srcPort = wrapper_ntohs(base->uh_sport);
        udp->dstPort = wrapper_ntohs(base->uh_dport);
        udp->dataLength = wrapper_ntohs(base->uh_ulen);
        udp->checksum = base->uh_sum;
        udp->data = (uint8_t *)ptr + udpHeaderSize;
        (*size) = udpHeaderSize;
        retVal = (int32_t)UDP_HEADER_RETURN_OK;
    }

    return retVal;
}

static uint16_t calcChksum(const uint8_t *header, const uint8_t *data, size_t headerSize, uint16_t dataLength) {
    register uint16_t sum;

    // calculate header
    sum = calcTotal(header, (int32_t)headerSize, 0);
    // calculate data
    sum = calcTotal(data, (int32_t)dataLength, sum);

    return (~sum);
}
