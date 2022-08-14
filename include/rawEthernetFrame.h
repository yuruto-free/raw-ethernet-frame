#ifndef RAWETHERNETFRAME_H_
#define RAWETHERNETFRAME_H_
#include <stdint.h>
#define REF_SUCCESS (0)
#define REF_FAILED (1)
// for ether header
#define REF_MACADDR_LENGTH (6)
// for TCP/UDP header
#define REF_USE_TCP (0x06)
#define REF_USE_UDP (0x11)
// for dump function
#define REF_ETHER_PACKET (0x01)
#define REF_IP_PACKET (0x02)
#define REF_UDP_PACKET (0x03)
#define REF_TCP_PACKET (0x04)

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
        uint8_t protocol; // REF_USE_TCP or REF_USE_UDP
        uint8_t padding;
        uint16_t fragOffset;
        uint16_t id;
        uint32_t srcAddr;
        uint32_t dstAddr;
    } ip;
    // UDP header
    struct {
        uint16_t srcPort;
        uint16_t dstPort;
        uint16_t dataLength;
        uint16_t padding;
    } udp;
    // TCP header
    struct {
        uint16_t srcPort;
        uint16_t dstPort;
        uint32_t seqNum;
        uint32_t ackNum;
        uint16_t windowSize;
        uint16_t urgentPointer;
        uint16_t dataLength;
        uint16_t optionLength;
        uint8_t flags;
        //
        // === The flags is defined by following structure ===
        //
        //     1bit  2bit  3bit  4bit  5bit  6bit  7bit  8bit
        //   +-----+-----+-----+-----+-----+-----+-----+-----+
        //   |  Reserved | URG | ACK | PSH | RST | SYN | FIN |
        //   +-----+-----+-----+-----+-----+-----+-----+-----+
        //   |<---   Upper Bit   --->|<---   Lower Bit   --->|
        //
        const uint8_t *options;
    } tcp;
    const uint8_t *data;
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
 * @brief
 *
 * @param[in]  frame  raw frame
 * @param[out] length total length
 * @return     REF_SUCCESS : success
 *             REF_FAILED  : failed
 */
int32_t REF_getTotalRawFrameLength(const struct REF_rawFrame_t *frame, int32_t *length);

/**
 * @brief get data from raw frame
 *
 * @param[in]  frame raw frame
 * @param[in]  idx   target index
 * @param[out] data  target data
 * @return     REF_SUCCESS : success
 *             REF_FAILED  : failed
 */
int32_t REF_getData(const struct REF_rawFrame_t *frame, int32_t idx, uint8_t *data);

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
