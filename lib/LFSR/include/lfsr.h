#pragma once
#include <stdint.h>
#include <stddef.h>
#include "tinkerbell.h" // uses your Tinkerbell class


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
    // chaosKey16: 16 bytes used to seed internal Tinkerbell for tap masks.
    ChaoticLFSR32(uint32_t seed, const uint8_t chaosKey16[16], uint32_t initialTap = 0xA3000001u)
      : state_(seed ? seed : 0xACE1u), taps_(initialTap ? initialTap : 0xA3000001u), byteCounter_(0)
    {
        // Derive a separate key for the internal tap-generator so it is independent
        // from the external Tinkerbell used for XOR in the pipeline.
        // Simple deterministic tweak: XOR each byte with 0x5A (or use a real KDF).
        uint8_t localKey[16];
        for (int i = 0; i < 16; ++i) localKey[i] = (chaosKey16 ? chaosKey16[i] ^ 0x5Au : (uint8_t)(i * 31 + 7));
        chaosTap_ = new Tinkerbell(localKey);
        // optional burn-in to decorrelate: match same number on encrypt/decrypt
        for (int i = 0; i < 32; ++i) (void)chaosTap_->nextByte();
    }

    ~ChaoticLFSR32() {
        if (chaosTap_) { delete chaosTap_; chaosTap_ = nullptr; }
    }

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
    Tinkerbell *chaosTap_;

    // produce a 32-bit tap mask from the internal tap-chaos generator
    uint32_t generateTapMaskFromChaos() {
        // deterministic: read 4 bytes from chaosTap_ and combine
        uint32_t m = 0;
        for (int i = 0; i < 4; ++i) {
            uint8_t b = chaosTap_->nextByte(); // consumes exactly 4 bytes per mask
            m = (m << 8) | b;
        }
        // ensure at least bit 0 is set (LSB) so parity feedback defined
        m |= 1u;
        // optional: force a few known taps to ensure maximal properties (if desired)
        byteCounter_++;
        return m;
    }

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