#ifndef RAWFRAME_H_
#define RAWFRAME_H_
#include <stdint.h>
#define REF_MAX_FRAME_LENGTH (1514)

struct REF_rawFrame_t {
    uint8_t buf[REF_MAX_FRAME_LENGTH];
    int32_t length;
};

#endif