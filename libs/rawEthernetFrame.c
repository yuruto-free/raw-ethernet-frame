#include <stddef.h>
#include <malloc.h>
#include <string.h>
#include "rawEthernetFrame.h"
#include "rawFrame.h"
#include "packetStructure.h"
#include "etherHeader.h"
#include "ipHeader.h"
#include "utils.h"

int32_t REF_mallocRawFrame(struct REF_rawFrame_t **frame) {
    int32_t retVal = (int32_t)REF_FAILED;

    if (NULL != frame) {
        (*frame) = (struct REF_rawFrame_t *)malloc(sizeof(struct REF_rawFrame_t));

        if (NULL == (*frame)) {
            goto EXIT_MALLOC_RAW_FRAME;
        }
        retVal = (int32_t)REF_SUCCESS;
    }

EXIT_MALLOC_RAW_FRAME:
    return retVal;
}

int32_t REF_freeRawFrame(struct REF_rawFrame_t **frame) {
    int32_t retVal = (int32_t)REF_FAILED;

    if ((NULL != frame) && (NULL != (*frame))) {
        free(*frame);
        retVal = (int32_t)REF_SUCCESS;
    }

    return retVal;
}

int32_t REF_createRawFrame(const struct REF_param_t *params, struct REF_rawFrame_t *frame) {
    int32_t retVal = (int32_t)REF_FAILED;
    int32_t funcVal;
    struct ip_header_arg_t ip;

    if ((NULL != params) && (NULL != frame)) {
        // initialize
        memset(frame->buf, 0x00, REF_MAX_FRAME_LENGTH);
        frame->length = 0;
        // setup Ether header (L2 layer)
        funcVal = setupEtherHeader(params->ether_header.dstMacAddr, params->ether_header.srcMacAddr, frame);
        if ((int32_t)ETHER_HEADER_RETURN_OK != funcVal) {
            goto EXIT_CREATE_RAW_FRAME;
        }
        // setup IP header (L3 layer)
        ip.ttl = params->ip.ttl;
        ip.tos = params->ip.tos;
        ip.protocol = params->ip.protocol;
        ip.fragOffset = params->ip.fragOffset;
        ip.id = params->ip.id;
        ip.srcAddr = params->ip.srcAddr;
        ip.dstAddr = params->ip.dstAddr;
        funcVal = setupIPHeader(&ip, frame);
        if ((int32_t)IP_HEADER_RETURN_OK != funcVal) {
            goto EXIT_CREATE_RAW_FRAME;
        }
        retVal = (int32_t)REF_SUCCESS;
    }

EXIT_CREATE_RAW_FRAME: 
    return retVal;
}

int32_t REF_dumpRawFrame(const struct REF_rawFrame_t *frame, REF_callback callback) {
    int32_t retVal = (int32_t)REF_FAILED;
    struct ether_header_t eth;
    struct ip_header_t ip;
    const uint8_t *ptr;
    size_t size;

    if ((NULL != frame) && (NULL != callback)) {
        // dump L2 layer (Ethernet layer)
        ptr = (const uint8_t *)(frame->buf);
        dumpEtherHeader(ptr, &eth, &size);
        callback((uint8_t)REF_ETHER_PACKET, (void *)&eth);
        ptr += size;
        dumpIPHeader(ptr, &ip, &size);
        callback((uint8_t)REF_IP_PACKET, (void *)&ip);

        retVal = (int32_t)REF_SUCCESS;
    }

    return retVal;
}

int32_t REF_convertMacAddrAscii2Network(const char *asciiFormat, uint8_t *networkFormat) {
    int32_t retVal = (int32_t)REF_FAILED;
    int32_t funcVal;

    if ((NULL != asciiFormat) && (NULL != networkFormat)) {
        funcVal = wrapper_ether_aton(asciiFormat, networkFormat, (size_t)REF_MACADDR_LENGTH);

        if ((int32_t)UTILS_RETURN_OK != funcVal) {
            goto EXIT_CONVERT_MACADDR_ASCII2NETWORK;
        }
        retVal = (int32_t)REF_SUCCESS;
    }

EXIT_CONVERT_MACADDR_ASCII2NETWORK:
    return retVal;
}

int32_t REF_convertMacAddrNetwork2Ascii(const uint8_t *networkFormat, char **asciiFormat) {
    int32_t retVal = (int32_t)REF_FAILED;
    int32_t funcVal;

    if ((NULL != networkFormat) && (NULL != asciiFormat)) {
        funcVal = wrapper_ether_ntoa(networkFormat, asciiFormat, (size_t)REF_ETHER_MACADDR_LENGTH);

        if ((int32_t)UTILS_RETURN_OK != funcVal) {
            goto EXIT_CONVERT_MACADDR_NETWORK2ASCII;
        }
        retVal = (int32_t)REF_SUCCESS;
    }

EXIT_CONVERT_MACADDR_NETWORK2ASCII:
    return retVal;
}

int32_t REF_convertIPAddrAscii2Network(const char *asciiFormat, uint32_t *networkFormat) {
    int32_t retVal = (int32_t)REF_FAILED;
    int32_t funcVal;

    if ((NULL != asciiFormat) && (NULL != networkFormat)) {
        funcVal = wrapper_ip_aton(asciiFormat, networkFormat);

        if ((int32_t)UTILS_RETURN_OK != funcVal) {
            goto EXIT_CONVERT_IPADDR_ASCII2NETWORK;
        }
        retVal = (int32_t)REF_SUCCESS;
    }

EXIT_CONVERT_IPADDR_ASCII2NETWORK:
    return retVal;
}

int32_t REF_convertIPAddrNetwork2Ascii(uint32_t networkFormat, char **asciiFormat) {
    int32_t retVal = (int32_t)REF_FAILED;
    int32_t funcVal;

    if (NULL != asciiFormat) {
        funcVal = wrapper_ip_ntoa(networkFormat, asciiFormat);

        if ((int32_t)UTILS_RETURN_OK != funcVal) {
            goto EXIT_CONVERT_IPADDR_NETWORK2ASCII;
        }
        retVal = (int32_t)REF_SUCCESS;
    }

EXIT_CONVERT_IPADDR_NETWORK2ASCII:
    return retVal;
}
