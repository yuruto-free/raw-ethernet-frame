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
    size_t size = sizeof(struct ether_header);
    memset(&eth, 0x00, size);

    if ((NULL != dstMacAddr) && (NULL != srcMacAddr) && (NULL != frame)) {
        memcpy(eth.ether_dhost, dstMacAddr, sizeof(eth.ether_dhost));
        memcpy(eth.ether_shost, srcMacAddr, sizeof(eth.ether_shost));
        eth.ether_type = wrapper_htos(ETHERTYPE_IP);
        memcpy(&frame->buf[frame->length], &eth, size);
        frame->length += (int32_t)size;

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
        (*size) = sizeof(struct ether_header);

        retVal = (int32_t)ETHER_HEADER_RETURN_OK;
    }

    return retVal;
}
