/**
 * tinkerbell.h - Tinkerbell chaotic map keystream generator (improved whitening)
 * x_{n+1} = x_n^2 - y_n^2 + a*x_n + b*y_n
 * y_{n+1} = 2*x_n*y_n + c*x_n + d*y_n
 *
 * Parameters derived from 8-byte key:
 *  a in [-0.90, -0.50], b in [-0.80, -0.40], c in [1.80, 2.20], d in [0.70, 1.10]
 *  x0, y0 as 16-bit fractions in (0,1)
 *
 * Whitening: mixes bits from x and y into a 32-bit xorshift state to reduce bias
 */
#pragma once
#include <stdint.h>
#include <stddef.h>

struct TinkerbellParams {
  double a, b, c, d;
  double x, y;
};

class Tinkerbell {
public:
  explicit Tinkerbell(const uint8_t chaosKey[8]);
  const TinkerbellParams& params() const { return p_; }

  // Generate bytes of keystream; internally mixes 8 iterations per byte
  void generate(uint8_t* out, size_t bytes);

  // XOR bitwise: data[i] ^= keystream_byte (LSB-first per byte)
  void xorBitwise(uint8_t* data, size_t len);

private:
  TinkerbellParams p_;
  uint32_t s_; // whitening state from key

  inline uint8_t nextBit();   // iterate map and emit 1 mixed bit
  inline uint8_t nextByte();  // 8 bits
  static double mapRange(uint8_t v, double lo, double hi);
  static double fracFrom16(uint8_t hi, uint8_t lo);
  static inline uint32_t rotl32(uint32_t x, int r) { return (x << r) | (x >> (32 - r)); }
};
