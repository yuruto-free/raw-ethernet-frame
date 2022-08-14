#include <net/ethernet.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "packetStructure.h"
#include "etherHeader.h"
#include "utils.h"

int32_t setupEtherHeader(const uint8_t *dstMacAddr, const uint8_t *srcMacAddr, struct REF_rawFrame_t *frame) {
    int32_t retVal = (int32_t)ETHER_HEADER_RETURN_NG;
    struct ether_header eth;
    size_t etherHeaderSize = sizeof(struct ether_header);
    uint8_t *ptr;
    memset(&eth, 0x00, etherHeaderSize);

    if ((NULL != dstMacAddr) && (NULL != srcMacAddr) && (NULL != frame)) {
        memcpy(eth.ether_dhost, dstMacAddr, sizeof(eth.ether_dhost));
        memcpy(eth.ether_shost, srcMacAddr, sizeof(eth.ether_shost));
        eth.ether_type = wrapper_htons(ETHERTYPE_IP);
        // update raw frame
        ptr = &(frame->buf[frame->length]);
        memcpy(ptr, &eth, etherHeaderSize);
        frame->length += (int32_t)etherHeaderSize;
        retVal = (int32_t)ETHER_HEADER_RETURN_OK;
    }

    return retVal;
}

int32_t dumpEtherHeader(const uint8_t *ptr, struct ether_header_t *eth, size_t *size) {
    int32_t retVal = (int32_t)ETHER_HEADER_RETURN_NG;
    struct ether_header *base;
    char *addr;

    if ((NULL != ptr) && (NULL != eth) && (NULL != size)) {
        base = (struct ether_header *)ptr;
        addr = eth->dstMacAddr;
        wrapper_ether_ntoa((const uint8_t *)(base->ether_dhost), &addr, (size_t)REF_ETHER_MACADDR_LENGTH);
        addr = eth->srcMacAddr;
        wrapper_ether_ntoa((const uint8_t *)(base->ether_shost), &addr, (size_t)REF_ETHER_MACADDR_LENGTH);
        eth->etherType = wrapper_ntohs(base->ether_type);
        eth->padding = 0;
        (*size) = sizeof(struct ether_header);
        retVal = (int32_t)ETHER_HEADER_RETURN_OK;
    }

    return retVal;
}
