/**
 * tinkerbell.h - Tinkerbell chaotic map keystream generator (improved whitening)
 * x_{n+1} = x_n^2 - y_n^2 + a*x_n + b*y_n
 * y_{n+1} = 2*x_n*y_n + c*x_n + d*y_n
 *
 * Parameters derived from 16-byte key:
 *  a in [-1.2, -0.3], b in [-1.0, -0.2], c in [1.5, 2.5], d in [0.3, 1.3]
 *  x0, y0 as 16-bit fractions in (0,1)
 *  Polynomial mixing coefficients for enhanced entropy
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

struct TinkerCoeffs {
  float alpha, beta;    // linear coefficients
  float gamma, delta;   // quadratic coefficients  
  float eps;           // cross term coefficient
  float zeta, eta;     // cubic coefficients
};

class Tinkerbell {
public:
  explicit Tinkerbell(const uint8_t chaosKey[16]);
  const TinkerbellParams& params() const { return p_; }

  // Generate bytes of keystream; internally mixes 8 iterations per byte
  void generate(uint8_t* out, size_t bytes);

  // XOR bitwise: data[i] ^= keystream_byte (LSB-first per byte)
  void xorBitwise(uint8_t* data, size_t len);

  // Generate one 8-bit keystream byte (for use by other components)
  uint8_t nextByte();

private:
  TinkerbellParams p_;
  TinkerCoeffs coeff_;
  uint32_t s_;
  uint32_t inc_;
  int rot1_, rot2_;

  inline uint8_t nextBit();   // iterate map and emit 1 mixed bit
  static double mapRange(uint8_t v, double lo, double hi);
  static double fracFrom16(uint8_t hi, uint8_t lo);
  static inline uint32_t rotl32(uint32_t x, int r) { return (x << r) | (x >> (32 - r)); }
};

/*
~ Generates a chaotic keystream that:
  - Has high entropy from the chaotic map.
  - Is hardened with polynomial nonlinearity.
  - Is statistically whitened to avoid bias.
~ Acts as a core PRNG for encryption in hybrid cryptographic system.
~ Uses key-dependent chaos parameters, meaning different keys lead to completely different trajectories.
*/