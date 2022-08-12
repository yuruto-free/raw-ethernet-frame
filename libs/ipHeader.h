#ifndef IP_HEADER_H_
#define IP_HEADER_H_
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
 * @param arg      function arguments
 * @param protocol protocol type
 * @param frame    raw frame
 * @return IP_HEADER_RETURN_OK : success
 *         IP_HEADER_RETURN_NG : failed
 */
int32_t setupIPHeader(const struct ip_header_arg_t *arg, struct REF_rawFrame_t *frame);

/**
 * @brief dump ip header of raw frame
 * 
 * @param ptr  raw data
 * @param ip   ip header packet
 * @param size packet length
 * @return IP_HEADER_RETURN_OK : success
 *         IP_HEADER_RETURN_NG : failed 
 */
int32_t dumpIPHeader(const uint8_t *ptr, struct ip_header_t *ip, size_t *size);

#endif