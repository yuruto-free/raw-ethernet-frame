#ifndef IP_HEADER_H_
#define IP_HEADER_H_
#include "rawFrame.h"
#define IP_HEADER_RETURN_OK (0)
#define IP_HEADER_RETURN_NG (1)

struct ip_header_arg_t {
    uint8_t ttl;
    uint8_t tos;
    uint8_t protocol;
    uint8_t padding;
    uint16_t fragOffset;
    uint16_t id;
    uint32_t srcAddr;
    uint32_t dstAddr;
};

/**
 * @brief setup ip header
 *
 * @param[in]  arg                function arguments
 * @param[in]  transportLayerSize transport layer size
 * @param[out] frame              raw frame
 * @return     IP_HEADER_RETURN_OK : success
 *             IP_HEADER_RETURN_NG : failed
 */
int32_t setupIPHeader(const struct ip_header_arg_t *arg, size_t transportLayerSize, struct REF_rawFrame_t *frame);

/**
 * @brief dump ip header of raw frame
 *
 * @param[in]  ptr  raw data
 * @param[out] ip   ip header packet
 * @param[out] size packet length
 * @return     IP_HEADER_RETURN_OK : success
 *             IP_HEADER_RETURN_NG : failed
 */
int32_t dumpIPHeader(const uint8_t *ptr, struct ip_header_t *ip, size_t *size);

#endif
