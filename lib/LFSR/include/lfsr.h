/**
 * lfsr.h - 16-bit LFSR keystream generator
 * Supports Fibonacci-style LFSR with configurable tap polynomial.
 * Default polynomial matches blueprint: x^16 + x^5 + x^3 + 1
 *
 * Polynomial encoding:
 *  - Use a 16-bit mask of taps excluding x^16 (MSB). For x^16 + x^5 + x^3 + 1,
 *    taps at positions {0, 2, 4} → mask 0b0001_0001_0001 = 0x0029.
 */
#pragma once
#include <stdint.h>
#include <stddef.h>

class LFSR16
{
public:
  // tapMask: bit i set means tap bit i of the state (bit0 = LSB)
  explicit LFSR16(uint16_t seed, uint16_t tapMask = 0x0029);
  void reseed(uint16_t seed);

  // Generate one 8-bit keystream byte (LSB-first internally)
  uint8_t nextByte();

  // Fill output with n keystream bytes
  void generate(uint8_t *out, size_t n);

  // XOR keystream with data buffer in-place
  void xorBuffer(uint8_t *buf, size_t n);

  uint16_t state() const { return state_; }
  uint16_t taps() const { return taps_; }

private:
  uint16_t state_;
  uint16_t taps_; // tap mask without the x^16 term

  // One LFSR step returns the output bit (LSB), then shifts with feedback
  uint8_t stepBit();
};
