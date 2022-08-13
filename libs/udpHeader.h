#ifndef UDP_HEADER_H_
#define UDP_HEADER_H_
#include "rawFrame.h"
#define UDP_HEADER_RETURN_OK (0)
#define UDP_HEADER_RETURN_NG (1)

struct udp_header_arg_t {
    uint32_t srcIPAddr;
    uint32_t dstIPAddr;
    uint16_t srcPort;
    uint16_t dstPort;
    uint16_t dataLength;
    const uint8_t *data;
};

/**
 * @brief setup udp header
 * 
 * @param[in]  arg   function argument
 * @param[out] frame raw frame
 * @return     UDP_HEADER_RETURN_OK : success
 *             UDP_HEADER_RETURN_NG : failed
 */
int32_t setupUdpHeader(const struct udp_header_arg_t *arg, struct REF_rawFrame_t *frame);

/**
 * @brief dump udp header of raw frame
 * 
 * @param[in]  ptr  raw data
 * @param[out] udp  udp header packet
 * @param[out] size packet length
 * @return     UDP_HEADER_RETURN_OK : success
 *             UDP_HEADER_RETURN_NG : failed 
 */
int32_t dumpUdpHeader(const uint8_t *ptr, struct udp_header_t *udp, size_t *size);

#endif
