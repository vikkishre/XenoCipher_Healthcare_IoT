#include "lfsr.h"
#if defined(ARDUINO) || defined(ESP_PLATFORM)
#include <Arduino.h>
#else
#include <cstdint>
#include <cstring>
#endif

// Efficient parity calculation for 32-bit
static inline uint8_t parity32(uint32_t x) {
    x ^= x >> 16;
    x ^= x >> 8;
    x ^= x >> 4;
    x ^= x >> 2;
    x ^= x >> 1;
    return x & 1;
}


