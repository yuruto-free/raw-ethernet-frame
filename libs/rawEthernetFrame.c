#include <stddef.h>
#include <malloc.h>
#include <string.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include "rawEthernetFrame.h"
#include "rawFrame.h"
#include "packetStructure.h"
#include "etherHeader.h"
#include "ipHeader.h"
#include "udpHeader.h"
#include "tcpHeader.h"
#include "utils.h"
#define FUNC_RETURN_OK (0)
#define FUNC_RETURN_NG (1)

struct transport_layer_t {
    size_t size;
    uint8_t protocol;
};

/**
 * @brief Get the transport layer infomation
 * 
 * @param[in]  protocol protocol type
 * @param[out] info     transport layer information
 * @return     FUNC_RETURN_OK : success
 *             FUNC_RETURN_NG : failed
 */
static int32_t getTransportLayerInfo(const struct REF_param_t *params, struct transport_layer_t *info);

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
    struct transport_layer_t info;
    struct ip_header_arg_t ip;
    struct udp_header_arg_t udp;
    struct tcp_header_arg_t tcp;

    if ((NULL != params) && (NULL != frame)) {
        // initialize
        memset(frame->buf, 0x00, REF_MAX_FRAME_LENGTH);
        frame->length = 0;
        // setup Ether header (L2 layer)
        funcVal = setupEtherHeader(params->eth.dstMacAddr, params->eth.srcMacAddr, frame);
        if ((int32_t)ETHER_HEADER_RETURN_OK != funcVal) {
            goto EXIT_CREATE_RAW_FRAME;
        }
        // setup IP header (L3 layer)
        funcVal = getTransportLayerInfo(params, &info);
        if ((int32_t)FUNC_RETURN_OK != funcVal) {
            goto EXIT_CREATE_RAW_FRAME;
        }
        ip.ttl = params->ip.ttl;
        ip.tos = params->ip.tos;
        ip.protocol = info.protocol;
        ip.fragOffset = params->ip.fragOffset;
        ip.id = params->ip.id;
        ip.srcAddr = params->ip.srcAddr;
        ip.dstAddr = params->ip.dstAddr;
        funcVal = setupIPHeader(&ip, info.size, frame);
        if ((int32_t)IP_HEADER_RETURN_OK != funcVal) {
            goto EXIT_CREATE_RAW_FRAME;
        }
        // setup udp header
        switch (params->ip.protocol) {
            case REF_USE_TCP:
                tcp.srcIPAddr = params->ip.srcAddr;
                tcp.srcPort = params->tcp.srcPort;
                tcp.dstIPAddr = params->ip.dstAddr;
                tcp.dstPort = params->tcp.dstPort;
                tcp.seqNum = params->tcp.seqNum;
                tcp.ackNum = params->tcp.ackNum;
                tcp.windowSize = params->tcp.windowSize;
                tcp.urgentPointer = params->tcp.urgentPointer;
                tcp.dataLength = params->tcp.dataLength;
                tcp.optionLength = params->tcp.optionLength;
                tcp.flags = params->tcp.flags;
                tcp.options = params->tcp.options;
                tcp.data = params->data;
                funcVal = setupTcpHeader(&tcp, frame);
                if ((int32_t)TCP_HEADER_RETURN_OK != funcVal) {
                    goto EXIT_CREATE_RAW_FRAME;
                }
                break;

            case REF_USE_UDP:
                udp.srcIPAddr = params->ip.srcAddr;
                udp.srcPort = params->udp.srcPort;
                udp.dstIPAddr = params->ip.dstAddr;
                udp.dstPort = params->udp.dstPort;
                udp.dataLength = params->udp.dataLength;
                udp.data = (const uint8_t *)(params->data);
                funcVal = setupUdpHeader(&udp, frame);
                if ((int32_t)UDP_HEADER_RETURN_OK != funcVal) {
                    goto EXIT_CREATE_RAW_FRAME;
                }
                break;

            default:
                break;
        }
        retVal = (int32_t)REF_SUCCESS;
    }

EXIT_CREATE_RAW_FRAME: 
    return retVal;
}

int32_t REF_getTotalRawFrameLength(const struct REF_rawFrame_t *frame, int32_t *length) {
    int32_t retVal = (int32_t)REF_FAILED;

    if ((NULL != frame) && (NULL != length)) {
        (*length) = frame->length;
        retVal = (int32_t)REF_SUCCESS;
    }

    return retVal;
}

int32_t REF_getData(const struct REF_rawFrame_t *frame, int32_t idx, uint8_t *data) {
    int32_t retVal = (int32_t)REF_FAILED;

    if ((NULL != frame) && (NULL != data)) {
        if ((idx >= 0) && (idx < frame->length)) {
            (*data) = frame->buf[idx];
            retVal = (int32_t)REF_SUCCESS;
        }
    }

    return retVal;
}

int32_t REF_dumpRawFrame(const struct REF_rawFrame_t *frame, REF_callback callback) {
    int32_t retVal = (int32_t)REF_FAILED;
    struct ether_header_t eth;
    struct ip_header_t ip;
    struct udp_header_t udp;
    struct tcp_header_t tcp;
    const uint8_t *ptr;
    size_t size, ipHeaderLen;

    if ((NULL != frame) && (NULL != callback)) {
        ptr = (const uint8_t *)(frame->buf);
        // dump L2 layer (Ether header)
        (void)dumpEtherHeader(ptr, &eth, &size);
        (void)callback((uint8_t)REF_ETHER_PACKET, (void *)&eth);
        ptr += size;
        switch (eth.etherType) {
            case ETHERTYPE_IP:
                // dump L3 layer (IP header)
                (void)dumpIPHeader(ptr, &ip, &size);
                (void)callback((uint8_t)REF_IP_PACKET, (void *)&ip);
                ptr += size;
                ipHeaderLen = size;
                switch (ip.protocol) {
                    case IPPROTO_TCP:
                        // dump L4 layer (TCP header)
                        (void)dumpTcpHeader(ptr, &tcp, &size);
                        tcp.dataLength = ip.totalLength - (uint16_t)ipHeaderLen - (uint16_t)size;
                        (void)callback((uint8_t)REF_TCP_PACKET, (void *)&tcp);
                        ptr += (ip.totalLength - (uint16_t)ipHeaderLen);
                        break;

                    case IPPROTO_UDP:
                        // dump L4 layer (UDP header)
                        (void)dumpUdpHeader(ptr, &udp, &size);
                        (void)callback((uint8_t)REF_UDP_PACKET, (void *)&udp);
                        ptr += size;
                        break;

                    default:
                        break;
                }
                retVal = (int32_t)REF_SUCCESS;
                break;

            default:
                break;
        }
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

static int32_t getTransportLayerInfo(const struct REF_param_t *params, struct transport_layer_t *info) {
    int32_t retVal = (int32_t)FUNC_RETURN_NG;

    if (NULL != info) {
        switch (params->ip.protocol) {
            case REF_USE_TCP:
                info->size = sizeof(struct tcphdr) + (size_t)(params->tcp.optionLength) + (size_t)(params->tcp.dataLength);
                info->protocol = IPPROTO_TCP;
                retVal = (int32_t)FUNC_RETURN_OK;
                break;

            case REF_USE_UDP:
                info->size = sizeof(struct udphdr) + (size_t)(params->udp.dataLength);
                info->protocol = IPPROTO_UDP;
                retVal = (int32_t)FUNC_RETURN_OK;
                break;

            default:
                break;
        }
    }

    return retVal;
}