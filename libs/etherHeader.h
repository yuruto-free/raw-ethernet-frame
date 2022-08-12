#ifndef ETHER_HEADER_H_
#define ETHER_HEADER_H_
#include "rawFrame.h"
#define ETHER_HEADER_RETURN_OK (0)
#define ETHER_HEADER_RETURN_NG (1)

/**
 * @brief setup ether header
 * 
 * @param[in] dstMacAddr destination MAC address
 * @param[in] srcMacAddr source MAC address
 * @param[out] frame      raw frame
 * @return ETHER_HEADER_RETURN_OK : success
 *         ETHER_HEADER_RETURN_NG : failed
 */
int32_t setupEtherHeader(const uint8_t *dstMacAddr, const uint8_t *srcMacAddr, struct REF_rawFrame_t *frame);

/**
 * @brief dump ether header of raw frame
 * 
 * @param[in] ptr   raw data
 * @param[out] eth  ether header packet
 * @param[out] size packet length
 * @return ETHER_HEADER_RETURN_OK : success
 *         ETHER_HEADER_RETURN_NG : failed
 */
int32_t dumpEtherHeader(const uint8_t *ptr, struct ether_header_t *eth, size_t *size);

#endif