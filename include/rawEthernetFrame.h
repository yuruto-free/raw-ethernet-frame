#ifndef RAWETHERNETFRAME_H_
#define RAWETHERNETFRAME_H_
#include <stdint.h>
#define REF_SUCCESS (0)
#define REF_FAILED (1)
#define REF_MACADDR_LENGTH (6)
#define REF_ETHER_PACKET (0x01)
#define REF_IP_PACKET (0x02)
#define REF_UDP_PACKET (0x03)
#define REF_TCP_PACKET (0x03)

// forward declaration
struct REF_rawFrame_t;
// callback
typedef int32_t (*REF_callback)(uint8_t packetType, void *data);

struct REF_param_t {
    // Ether header
    struct {
        uint8_t dstMacAddr[REF_MACADDR_LENGTH]; // destination MAC address
        uint8_t srcMacAddr[REF_MACADDR_LENGTH]; // source MAC address
    } ether_header;
    // IP header
    struct {
        uint8_t ttl;
        uint8_t tos; // type of service
        uint8_t protocol; // REF_USE_TCP or REF_USE_UDP (packetStructure.h)
        uint8_t padding;
        uint16_t fragOffset;
        uint16_t id;
        uint32_t srcAddr;
        uint32_t dstAddr;
    } ip;
};

/**
 * @brief malloc raw frame
 * 
 * @param[out] frame raw frame
 * @return     REF_SUCCESS : success
 *             REF_FAILED  : failed 
 */
int32_t REF_mallocRawFrame(struct REF_rawFrame_t **frame);

/**
 * @brief free raw frame
 * 
 * @param[inout] frame raw frame
 * @return       REF_SUCCESS : success
 *               REF_FAILED  : failed 
 */
int32_t REF_freeRawFrame(struct REF_rawFrame_t **frame);

/**
 * @brief create raw frame
 * 
 * @param[in]  params ethernet frame parameters
 * @param[out] frame  raw frame
 * @return     REF_SUCCESS : success
 *             REF_FAILED  : failed
 */
int32_t REF_createRawFrame(const struct REF_param_t *params, struct REF_rawFrame_t *frame);

/**
 * @brief dump raw frame
 * 
 * @param[in] frame    raw frame
 * @param[in] callback callback function to dump frame data
 * @return    REF_SUCCESS : success
 *            REF_FAILED  : failed
 */
int32_t REF_dumpRawFrame(const struct REF_rawFrame_t *frame, REF_callback callback);

/**
 * @brief convert mac address in ascii format to network format
 * 
 * @param[in]  asciiFormat   mac address in ascii format
 * @param[out] networkFormat mac address in network format
 * @return     REF_SUCCESS : success
 *             REF_FAILED  : failed
 */
int32_t REF_convertMacAddrAscii2Network(const char *asciiFormat, uint8_t *networkFormat);

/**
 * @brief convert mac address in network format to ascii format
 * 
 * @param[in]  networkFormat mac address in network format
 * @param[out] asciiFormat   mac address in ascii format
 * @return     REF_SUCCESS : success
 *             REF_FAILED  : failed
 */
int32_t REF_convertMacAddrNetwork2Ascii(const uint8_t *networkFormat, char **asciiFormat);

/**
 * @brief convert ip address in ascii format to network format
 * 
 * @param[in]  asciiFormat   ip address in ascii format
 * @param[out] networkFormat ip address in network format
 * @return     REF_SUCCESS : success
 *             REF_FAILED  : failed
 */
int32_t REF_convertIPAddrAscii2Network(const char *asciiFormat, uint32_t *networkFormat);

/**
 * @brief convert ip address in network format to ascii format
 * 
 * @param[in]  networkFormat ip address in network format
 * @param[out] asciiFormat   ip address in ascii format
 * @return     REF_SUCCESS : success
 *             REF_FAILED  : failed
 */
int32_t REF_convertIPAddrNetwork2Ascii(uint32_t networkFormat, char **asciiFormat);

#endif