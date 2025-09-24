#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stddef.h>
#include <stdint.h>


// 16-bit LFSR (kept for compatibility)
class LFSR16 {
public:
  LFSR16(uint16_t seed, uint16_t tapMask)
    : state_(seed ? seed : 1), taps_(tapMask ? tapMask : 0x0029) {}
  void reseed(uint16_t seed) { state_ = seed ? seed : 1; }
  uint8_t stepBit() {
    uint8_t out = (uint8_t)(state_ & 1u);
    // Compute parity of tapped bits
    uint16_t x = state_ & taps_;
    x ^= x >> 8;
    x ^= x >> 4;
    x ^= x >> 2;
    x ^= x >> 1;
    uint8_t fb = x & 1;
    state_ = (uint16_t)((state_ >> 1) | (uint16_t)(fb << 15));
    return out;
  }
  uint8_t nextByte() { uint8_t b = 0; for (int i = 0; i < 8; ++i) b |= (stepBit() << i); return b; }
  void generate(uint8_t* out, size_t n) { for (size_t i = 0; i < n; ++i) out[i] = nextByte(); }
  void xorBuffer(uint8_t* buf, size_t n) { for (size_t i = 0; i < n; ++i) buf[i] ^= nextByte(); }

private:
  uint16_t state_;
  uint16_t taps_;
};

/**
 * @brief 32-bit Linear Feedback Shift Register (LFSR) PRNG
 * 
 * Generates pseudo-random bytes using a configurable feedback polynomial.
 * Default taps mask (0xA3000001) is chosen for good randomness properties.
 */
class ChaoticLFSR32 {
public:
    // chaosKey16: 16 bytes used to seed deterministic tap-mask stream (platform-stable)
    ChaoticLFSR32(uint32_t seed, const uint8_t chaosKey16[16], uint32_t initialTap = 0xA3000001u);

    ~ChaoticLFSR32() {}

    // reseed without touching chaosTap_ (chaosTap_ seeded on construction)
    void reseed(uint32_t seed) {
        state_ = seed ? seed : 0xACE1u;
        byteCounter_ = 0;
    }

    // generate bytes (keystream)
    void generate(uint8_t *out, size_t n) {
        for (size_t i = 0; i < n; ++i) {
            // update taps once per byte deterministically
            taps_ = generateTapMaskFromChaos();
            out[i] = nextByte_internal();
        }
    }

    // XOR a buffer with the keystream
    void xorBuffer(uint8_t *buf, size_t n) {
        for (size_t i = 0; i < n; ++i) {
            taps_ = generateTapMaskFromChaos();
            buf[i] ^= nextByte_internal();
        }
    }

private:
    uint32_t state_;
    uint32_t taps_;
    uint64_t byteCounter_;
    // HMAC-based deterministic keystream state
    uint8_t key16_[16];
    uint32_t seedBe_;
    uint8_t block_[32];
    size_t blockIndex_;
    uint32_t blockCounter_;

    // produce a 32-bit tap mask from the internal tap-chaos generator
    uint8_t nextKeystreamByte();
    uint32_t generateTapMaskFromChaos();

    // internal nextByte that uses current taps_
    uint8_t nextByte_internal() {
        uint8_t b = 0;
        for (int i = 0; i < 8; ++i) {
            b |= (stepBit_internal() << i);
        }
        return b;
    }

    uint8_t stepBit_internal() {
        uint8_t out = (uint8_t)(state_ & 1u);
        uint32_t v = state_ & taps_;
        // parity fallback
        v ^= v >> 16; v ^= v >> 8; v ^= v >> 4; v ^= v >> 2; v ^= v >> 1;
        uint8_t fb = (uint8_t)(v & 1u);
        state_ = (state_ >> 1) | ((uint32_t)fb << 31);
        return out;
    }
};