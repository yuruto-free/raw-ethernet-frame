#ifndef UTILS_H_
#define UTILS_H_
#include <stdint.h>
#define UTILS_RETURN_OK (0)
#define UTILS_RETURN_NG (1)

/**
 * @brief calculate total
 *
 * @param[in] data      target data
 * @param[in] size      data length
 * @param[in] initValue initialized value
 * @return sum
 */
uint16_t calcTotal(const uint8_t *data, int32_t size, uint16_t initValue);

/**
 * @brief convert mac address in ascii format to network format
 *
 * @param[in]  asciiFormat   mac address in ascii format
 * @param[out] networkFormat mac address in network format
 * @param[in]  size          network format size
 * @return     UTILS_RETURN_OK : success
 *             UTILS_RETURN_NG : failed
 */
int32_t wrapper_ether_aton(const char *asciiAddr, uint8_t *networkAddr, size_t size);
/**
 * @brief convert mac address in network format to ascii format
 *
 * @param[in]  networkAddr mac address in network format
 * @param[out] asciiAddr   mac address in ascii format
 * @param[in]  size        ascii format size
 * @return     UTILS_RETURN_OK : success
 *             UTILS_RETURN_NG : failed
 */
int32_t wrapper_ether_ntoa(const uint8_t *networkAddr, char **asciiAddr, size_t size);
/**
 * @brief convert ip address in ascii format to network format
 *
 * @param[in]  asciiAddr   ip address in ascii format
 * @param[out] netwrokAddr ip address in network format
 * @return     UTILS_RETURN_OK : success
 *             UTILS_RETURN_NG : failed
 */
int32_t wrapper_ip_aton(const char *asciiAddr, uint32_t *netwrokAddr);
/**
 * @brief convert ip address in network format to ascii format
 *
 * @param[in]  networkAddr ip address in network format
 * @param[out] asciiAddr   ip address in ascii format
 * @return     UTILS_RETURN_OK : success
 *             UTILS_RETURN_NG : failed
 */
int32_t wrapper_ip_ntoa(uint32_t networkAddr, char **asciiAddr);

/**
 * @brief convert host byte order to network byte order
 *
 * @param[in] hostshort data of host byte order
 * @return networkshort
 */
uint16_t wrapper_htons(uint16_t hostshort);

/**
 * @brief convert network byte order to host byte order
 *
 * @param networkshort data of network byte order
 * @return hostshort
 */
uint16_t wrapper_ntohs(uint16_t networkshort);

/**
 * @brief convert host byte order to network byte order
 *
 * @param[in] hostlong data of host byte order
 * @return networklong
 */
uint32_t wrapper_htonl(uint16_t hostlong);

/**
 * @brief convert network byte order to host byte order
 *
 * @param networklong data of network byte order
 * @return hostlong
 */
uint32_t wrapper_ntohl(uint16_t networklong);

#endif
