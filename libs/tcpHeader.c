#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "packetStructure.h"
#include "tcpHeader.h"
#include "utils.h"
#define CALC_DATA_OFFSET(x) ((x) / 4)
#define UPDATE_PSEUDO_DATAOFFSET(x) ((CALC_DATA_OFFSET(x) << 4) & 0xF0)
#define GET_DATAOFFSET(doff) ((doff) * 4)

struct pseudo_header_t {
    uint32_t srcIPAddr;
    uint32_t dstIPAddr;
    uint16_t protocol; // reserved(uint8_t) + protocol(uint8_t)
    uint16_t dataLength;
    uint16_t srcPort;
    uint16_t dstPort;
    uint32_t seqNum;
    uint32_t ackNum;
    uint8_t dataOffset;
    uint8_t flags;
    uint16_t windowSize;
    uint16_t checksum;
    uint16_t urgentPointer;
};

struct checksum_arg_t {
    struct pseudo_header_t pseudoHeader;
    uint16_t optionLength;
    uint16_t dataLength;
    const uint8_t *options;
    const uint8_t *data;
};

/**
 * @brief calculate checksum of tcp header
 *
 * @param[in] arg function argument
 * @return checksum
 */
static uint16_t calcChksum(const struct checksum_arg_t *arg);

int32_t setupTcpHeader(const struct tcp_header_arg_t *arg, struct REF_rawFrame_t *frame) {
    int32_t retVal = (int32_t)TCP_HEADER_RETURN_NG;
    struct tcphdr tcp;
    struct checksum_arg_t chksumArg;
    uint8_t flags;
    uint16_t tcpBaseSize, tcpHeaderSize;
    uint8_t *ptr;

    if ((NULL != arg) && (NULL != frame)) {
        flags = arg->flags;
        chksumArg.optionLength = arg->optionLength;
        chksumArg.dataLength = arg->dataLength;
        chksumArg.options = arg->options;
        chksumArg.data = arg->data;
        tcpBaseSize = (uint16_t)sizeof(struct tcphdr);
        tcpHeaderSize = tcpBaseSize + chksumArg.optionLength;
        // setup tcp header
        tcp.source = wrapper_htons(arg->srcPort);
        tcp.dest = wrapper_htons(arg->dstPort);
        tcp.seq = wrapper_htonl(arg->seqNum);
        tcp.ack_seq = wrapper_htonl(arg->ackNum);
        tcp.th_x2 = 0;
        tcp.th_off = (uint8_t)CALC_DATA_OFFSET(tcpHeaderSize);
        tcp.th_flags = flags;
        tcp.window = wrapper_htons(arg->windowSize);
        tcp.urg_ptr = wrapper_htons(arg->urgentPointer);
        tcp.check = 0;
        // setup pseudo header
        chksumArg.pseudoHeader.srcIPAddr = arg->srcIPAddr;
        chksumArg.pseudoHeader.dstIPAddr = arg->dstIPAddr;
        chksumArg.pseudoHeader.protocol = wrapper_htons((uint16_t)IPPROTO_TCP);
        chksumArg.pseudoHeader.dataLength = wrapper_htons(tcpHeaderSize + arg->dataLength);
        chksumArg.pseudoHeader.srcPort = tcp.source;
        chksumArg.pseudoHeader.dstPort = tcp.dest;
        chksumArg.pseudoHeader.seqNum = tcp.seq;
        chksumArg.pseudoHeader.ackNum = tcp.ack_seq;
        chksumArg.pseudoHeader.dataOffset = (uint8_t)UPDATE_PSEUDO_DATAOFFSET(tcpHeaderSize);
        chksumArg.pseudoHeader.flags = flags;
        chksumArg.pseudoHeader.windowSize = tcp.window;
        chksumArg.pseudoHeader.checksum = 0;
        chksumArg.pseudoHeader.urgentPointer = tcp.urg_ptr;
        // calculate checksum
        tcp.check = calcChksum((const struct checksum_arg_t *)&chksumArg);
        // update raw frame
        ptr = &(frame->buf[frame->length]);
        memcpy(ptr, &tcp, tcpBaseSize);
        ptr += (size_t)tcpBaseSize;
        memcpy(ptr, arg->options, chksumArg.optionLength);
        ptr += (size_t)chksumArg.optionLength;
        memcpy(ptr, arg->data, arg->dataLength);
        frame->length += (int32_t)(tcpBaseSize + chksumArg.optionLength + arg->dataLength);
        retVal = (int32_t)TCP_HEADER_RETURN_OK;
    }

    return retVal;
}

int32_t dumpTcpHeader(const uint8_t *ptr, struct tcp_header_t *tcp, size_t *offset) {
    int32_t retVal = (int32_t)TCP_HEADER_RETURN_NG;
    const struct tcphdr *base;
    uint16_t tcpHeaderSize;

    if ((NULL != ptr) && (NULL != tcp) && (NULL != offset)) {
        base = (const struct tcphdr *)ptr;
        tcpHeaderSize = (uint16_t)sizeof(struct tcphdr);
        tcp->srcPort = wrapper_ntohs(base->source);
        tcp->dstPort = wrapper_ntohs(base->dest);
        tcp->seqNum = wrapper_ntohl(base->seq);
        tcp->ackNum = wrapper_ntohl(base->ack_seq);
        tcp->dataOffset = base->th_off;
        tcp->flags = base->th_flags;
        tcp->windowSize = wrapper_ntohs(base->window);
        tcp->checksum = wrapper_ntohs(base->check);
        tcp->urgentPointer = wrapper_ntohs(base->urg_ptr);
        tcp->optionSize = (uint16_t)GET_DATAOFFSET((uint16_t)(base->th_off)) - tcpHeaderSize;
        if (0 != (tcp->optionSize)) {
            tcp->options = (uint8_t *)ptr + tcpHeaderSize;
        }
        else {
            tcp->options = NULL;
        }
        (*offset) = (size_t)GET_DATAOFFSET((uint16_t)(base->th_off));
        tcp->data = (uint8_t *)ptr + (*offset);
        retVal = (int32_t)TCP_HEADER_RETURN_OK;
    }

    return retVal;
}

static uint16_t calcChksum(const struct checksum_arg_t *arg) {
    register uint16_t sum;

    // calculate header
    sum = calcTotal((const uint8_t *)&(arg->pseudoHeader), (int32_t)sizeof(struct pseudo_header_t), 0);
    // calculate options
    sum = calcTotal(arg->options, (int32_t)(arg->optionLength), sum);
    // calculate data
    sum = calcTotal(arg->data, (int32_t)(arg->dataLength), sum);

    return (~sum);
}
