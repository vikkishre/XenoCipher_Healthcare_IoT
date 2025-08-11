#pragma once
#include <stdint.h>
#include <stddef.h>
#include <time.h>
#include <math.h>
#include <stdlib.h>

// ==================== Chaotic Map: Tinkerbell ====================
struct TinkerbellParams {
    double a, b, c, d;
    double x, y;
};

class Tinkerbell {
public:
    Tinkerbell(const uint8_t chaosKey[16]) {
        uint16_t v0 = ((uint16_t)chaosKey[0] << 8) | chaosKey[1];
        uint16_t v1 = ((uint16_t)chaosKey[2] << 8) | chaosKey[3];
        uint16_t v2 = ((uint16_t)chaosKey[4] << 8) | chaosKey[5];
        uint16_t v3 = ((uint16_t)chaosKey[6] << 8) | chaosKey[7];

        p_.a = mapRange(v0, -1.2, -0.3);
        p_.b = mapRange(v1, -1.0, -0.2);
        p_.c = mapRange(v2,  1.5,  2.5);
        p_.d = mapRange(v3,  0.3,  1.3);

        p_.x = fracFrom16(chaosKey[8], chaosKey[9]);
        p_.y = fracFrom16(chaosKey[10], chaosKey[11]);

        // Burn-in iterations
        for (int i = 0; i < 64; ++i) step();
    }

    // Step once in the chaotic map
    double step() {
        double xn = p_.x;
        double yn = p_.y;
        double x1 = xn * xn - yn * yn + p_.a * xn + p_.b * yn;
        double y1 = 2.0 * xn * yn + p_.c * xn + p_.d * yn;
        p_.x = x1;
        p_.y = y1;
        return fabs(p_.x + p_.y); // combined magnitude
    }

private:
    TinkerbellParams p_;

    static double mapRange(uint16_t v, double lo, double hi) {
        return lo + (double(v) / 65535.0) * (hi - lo);
    }

    static double fracFrom16(uint8_t hi, uint8_t lo) {
        uint16_t u = ((uint16_t)hi << 8) | lo;
        double f = ((double)u + 1.0) / 65536.0;
        return (f >= 1.0) ? 0.999984741 : f;
    }
};

// ==================== Chaotic LFSR32 ====================
class ChaoticLFSR32 {
public:
    ChaoticLFSR32(uint32_t seed, const uint8_t chaosKey[16])
    : chaos_(chaosKey)
    {
        reseed(seed);
    }

    void reseed(uint32_t seed) {
        // Seed mixing
        uint32_t t = (uint32_t)time(NULL);
        uint32_t hw = hwRandom();
        uint32_t mixed_seed = seed ^ t ^ hw ^ ((seed << 13) | (seed >> 19));
        state_ = mixed_seed ? mixed_seed : 0xACE1u;
        taps_ = generateTapMaskFromChaos();
    }

    uint8_t stepBit() {
        // Periodically update taps from chaos
        if ((bitCounter_++ % 64) == 0) { // every 64 bits
            taps_ = generateTapMaskFromChaos();
        }

        uint8_t out = (uint8_t)(state_ & 1u);

#if defined(__GNUC__)
        uint8_t fb = __builtin_parity(state_ & taps_);
#else
        uint32_t v = state_ & taps_;
        v ^= v >> 16; v ^= v >> 8; v ^= v >> 4; v ^= v >> 2; v ^= v >> 1;
        uint8_t fb = (uint8_t)(v & 1u);
#endif

        state_ = (state_ >> 1) | ((uint32_t)fb << 31);
        return out;
    }

    uint8_t nextByte() {
        uint8_t b = 0;
        for (int i = 0; i < 8; ++i) {
            b |= (stepBit() << i);
        }
        return b;
    }

    void generate(uint8_t *out, size_t n) {
        for (size_t i = 0; i < n; ++i) {
            out[i] = nextByte();
        }
    }

    void xorBuffer(uint8_t *buf, size_t n) {
        for (size_t i = 0; i < n; ++i) {
            buf[i] ^= nextByte();
        }
    }

private:
    uint32_t state_;
    uint32_t taps_;
    size_t bitCounter_ = 0;
    Tinkerbell chaos_;

    uint32_t generateTapMaskFromChaos() {
        double chaosVal = chaos_.step();
        uint32_t chaosBits = (uint32_t)(chaosVal * 0xFFFFFFFFu);
        chaosBits |= 1u; // ensure feedback tap at LSB
        return chaosBits;
    }

    static inline uint32_t hwRandom() {
        return (uint32_t)rand(); // Replace with hardware RNG if available
    }
};
