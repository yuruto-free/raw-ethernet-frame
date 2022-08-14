#include <netinet/ether.h>
#include <arpa/inet.h>
#include <stddef.h>
#include <string.h>
#include "utils.h"
#define CHECKSUM_MSB (0x80000000)
#define CHECKSUM_MASK (0x0000FFFF)
#define SHIFT_CHECKSUM(x) (((x) & (uint32_t)CHECKSUM_MASK) + (((x) >> 16) & (uint32_t)CHECKSUM_MASK))

uint16_t calcTotal(const uint8_t *data, int32_t size, uint16_t initValue) {
    register uint32_t sum;
    register const uint16_t *ptr;
    register int32_t idx;
    uint16_t val;

    sum = (uint32_t)initValue & (uint32_t)CHECKSUM_MASK;
    ptr = (const uint16_t *)data;

    for (idx = size; idx > 1; idx -= 2) {
        sum += (*ptr);
        // check overflow
        if (sum & (uint32_t)CHECKSUM_MSB) {
            sum = SHIFT_CHECKSUM(sum);
        }
        ptr++;
    }
    if (1 == idx) {
        val = 0;
        memcpy(&val, ptr, sizeof(uint8_t));
        sum += (uint32_t)(val & (uint16_t)0x00FF);
    }
    while (sum >> 16) {
        sum = SHIFT_CHECKSUM(sum);
    }

    return (uint16_t)(sum & (uint32_t)CHECKSUM_MASK);
}

int32_t wrapper_ether_aton(const char *asciiAddr, uint8_t *networkAddr, size_t size) {
    int32_t retVal = (int32_t)UTILS_RETURN_NG;
    struct ether_addr *addr;

    if ((NULL != asciiAddr) && (NULL != networkAddr)) {
        addr = ether_aton(asciiAddr);

        if (NULL == addr) {
            goto EXIT_WRAPPER_ETHER_ATON;
        }
        memcpy(networkAddr, addr, size);

        retVal = (int32_t)UTILS_RETURN_OK;
    }

EXIT_WRAPPER_ETHER_ATON:
    return retVal;
}

int32_t wrapper_ether_ntoa(const uint8_t *networkAddr, char **asciiAddr, size_t size) {
    int32_t retVal = (int32_t)UTILS_RETURN_NG;
    char *addr;

    if ((NULL != networkAddr) && (NULL != asciiAddr)) {
        addr = ether_ntoa((const struct ether_addr *)networkAddr);
        memcpy(*asciiAddr, addr, size);

        retVal = (int32_t)UTILS_RETURN_OK;
    }

    return retVal;
}

int32_t wrapper_ip_aton(const char *asciiAddr, uint32_t *netwrokAddr) {
    int32_t retVal = (int32_t)UTILS_RETURN_NG;
    int funcVal;

    if ((NULL != asciiAddr) && (NULL != netwrokAddr)) {
        funcVal = inet_aton(asciiAddr, (struct in_addr *)netwrokAddr);

        if (0 == funcVal) {
            goto EXIT_WRAPPER_IP_ATON;
        }
        retVal = (int32_t)UTILS_RETURN_OK;
    }

EXIT_WRAPPER_IP_ATON:
    return retVal;
}

int32_t wrapper_ip_ntoa(uint32_t networkAddr, char **asciiAddr) {
    int32_t retVal = (int32_t)UTILS_RETURN_NG;
    char *addr;

    if (NULL != asciiAddr) {
        addr = inet_ntoa(*((struct in_addr *)&networkAddr));
        memcpy(*asciiAddr, addr, strlen(addr) + 1);
    }

    return retVal;
}

uint16_t wrapper_htons(uint16_t hostshort) {
    return (uint16_t)htons(hostshort);
}

uint16_t wrapper_ntohs(uint16_t networkshort) {
    return (uint16_t)ntohs(networkshort);
}

uint32_t wrapper_htonl(uint32_t hostlong) {
    return (uint32_t)htonl(hostlong);
}

uint32_t wrapper_ntohl(uint32_t networklong) {
    return (uint32_t)ntohl(networklong);
}
