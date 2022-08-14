#ifndef TCP_HEADER_H_
#define TCP_HEADER_H_
#include "rawFrame.h"
#define TCP_HEADER_RETURN_OK (0)
#define TCP_HEADER_RETURN_NG (1)

struct tcp_header_arg_t {
    uint32_t srcIPAddr;
    uint32_t dstIPAddr;
    uint16_t srcPort;
    uint16_t dstPort;
    uint32_t seqNum;
    uint32_t ackNum;
    uint16_t windowSize;
    uint16_t urgentPointer;
    uint16_t dataLength;
    uint16_t optionLength;
    uint8_t flags;
    const uint8_t *options;
    const uint8_t *data;
};

/**
 * @brief setup tcp header
 * 
 * @param[in]  arg   function argument
 * @param[out] frame raw frame
 * @return     TCP_HEADER_RETURN_OK : success
 *             TCP_HEADER_RETURN_NG : failed
 */
int32_t setupTcpHeader(const struct tcp_header_arg_t *arg, struct REF_rawFrame_t *frame);

/**
 * @brief dump tcp header
 * 
 * @param[in]  ptr    raw data
 * @param[out] tcp    tcp header packet
 * @param[out] offset packet offset
 * @return     TCP_HEADER_RETURN_OK : success
 *             TCP_HEADER_RETURN_NG : failed 
 */
int32_t dumpTcpHeader(const uint8_t *ptr, struct tcp_header_t *tcp, size_t *offset);

#endif