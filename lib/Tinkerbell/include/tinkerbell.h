/**
 * tinkerbell.h - Tinkerbell chaotic map keystream generator
 * x_{n+1} = x_n^2 - y_n^2 + a*x_n + b*y_n
 * y_{n+1} = 2*x_n*y_n + c*x_n + d*y_n
 *
 * We derive parameters a,b,c,d and initial (x0,y0) from 8 bytes (chaosKey):
 *  - a in [-0.90, -0.50] from chaosKey[0]
 *  - b in [-0.80, -0.40] from chaosKey[1]
 *  - c in [ 1.80,  2.20] from chaosKey[2]
 *  - d in [ 0.70,  1.10] from chaosKey[3]
 *  - x0, y0 from 16-bit fractions (chaosKey[4..5], chaosKey[6..7]) in (0,1)
 *
 * Keystream: 1 bit per iteration from floor(x_{n+1} * 2^32) & 1
 * We pack 8 iterations into a byte for performance.
 */
#pragma once
#include <stdint.h>
#include <stddef.h>

struct TinkerbellParams
{
  double a, b, c, d;
  double x, y;
};

class Tinkerbell
{
public:
  explicit Tinkerbell(const uint8_t chaosKey[8]);
  const TinkerbellParams &params() const { return p_; }

  // Generate 'bytes' bytes (8*bytes iterations); pack 1-bit per iteration LSB-first
  void generate(uint8_t *out, size_t bytes);

  // XOR bitwise: for len bytes of data, we generate len*8 bits and XOR at bit granularity
  // data is modified in place
  void xorBitwise(uint8_t *data, size_t len);

private:
  TinkerbellParams p_;
  inline uint8_t nextBit(); // iterate once and emit keystream bit
  static double mapRange(uint8_t v, double lo, double hi);
  static double fracFrom16(uint8_t hi, uint8_t lo); // (1..65535)/65536
};
