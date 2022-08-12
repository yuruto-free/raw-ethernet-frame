#include <netinet/ether.h>
#include <arpa/inet.h>
#include <stddef.h>
#include <string.h>
#include "utils.h"

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
        memcpy(*asciiAddr, addr, strlen(addr));
    }

    return retVal;
}

uint16_t wrapper_htos(uint16_t hostshort) {
    return (uint16_t)htons(hostshort);
}

uint16_t wrapper_ntohs(uint16_t networkshort) {
    return (uint16_t)ntohs(networkshort);
}