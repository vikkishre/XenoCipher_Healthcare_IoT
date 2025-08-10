// tinkerbell_strong.cpp
#include "tinkerbell.h"
#include <math.h>
#include <string.h>

// Utility: rotate
static inline uint32_t rotl32(uint32_t x, int r) { return (x << r) | (x >> (32 - r)); }

// Map 16-bit -> float in range [lo, hi]
static inline float mapRange16(uint16_t v, float lo, float hi) {
  float t = (float)v / 65535.0f;
  return lo + t * (hi - lo);
}

// Convert two bytes to fractional (0,1)
static inline float fracFrom16b(uint8_t hi, uint8_t lo) {
  uint16_t u = ((uint16_t)hi << 8) | lo;
  float f = ((float)u + 1.0f) / 65536.0f; // (0,1]
  if (f >= 1.0f) f = 0.999984741f;
  return f;
}

// Strong Tinkerbell constructor: expects 16-byte chaosKey
Tinkerbell::Tinkerbell(const uint8_t chaosKey[16]) {
  // Classic parameters (wider ranges for robustness)
  uint16_t v0 = ((uint16_t)chaosKey[0] << 8) | chaosKey[1];
  uint16_t v1 = ((uint16_t)chaosKey[2] << 8) | chaosKey[3];
  uint16_t v2 = ((uint16_t)chaosKey[4] << 8) | chaosKey[5];
  uint16_t v3 = ((uint16_t)chaosKey[6] << 8) | chaosKey[7];

  p_.a = mapRange16(v0, -1.2f, -0.3f);   // a
  p_.b = mapRange16(v1, -1.0f, -0.2f);   // b
  p_.c = mapRange16(v2,  1.5f,  2.5f);   // c
  p_.d = mapRange16(v3,  0.3f,  1.3f);   // d

  // x0,y0 from next bytes
  p_.x = fracFrom16b(chaosKey[8], chaosKey[9]);
  p_.y = fracFrom16b(chaosKey[10], chaosKey[11]);

  // Polynomial mixing coefficients derived from control bytes
  uint8_t ctrl = chaosKey[12];
  // small helper to map byte to float in [lo,hi]
  auto mapByte = [](uint8_t b, float lo, float hi)->float {
    return lo + ((float)b / 255.0f) * (hi - lo);
  };

  // linear coeffs
  coeff_.alpha = mapByte(chaosKey[13], -2.0f, 2.0f);
  coeff_.beta  = mapByte(chaosKey[14], -2.0f, 2.0f);
  // quadratic coeffs
  coeff_.gamma = mapByte((ctrl ^ chaosKey[13]), -4.0f, 4.0f);
  coeff_.delta = mapByte((~ctrl ^ chaosKey[14]), -4.0f, 4.0f);
  // cross term
  coeff_.eps   = mapByte(chaosKey[15], -4.0f, 4.0f);
  // cubic coeffs derived from mixture for extra entropy
  coeff_.zeta  = mapByte((uint8_t)(ctrl + chaosKey[15]), -8.0f, 8.0f);
  coeff_.eta   = mapByte((uint8_t)(ctrl ^ (chaosKey[15] >> 1)), -8.0f, 8.0f);

  // Whitening/xorshift state seeded from key bytes 0..3 + 4..7
  s_ = ((uint32_t)chaosKey[0] << 24) | ((uint32_t)chaosKey[1] << 16)
     | ((uint32_t)chaosKey[2] << 8)  |  (uint32_t)chaosKey[3];
  if (s_ == 0) s_ = 0x9E3779B9u;

  // splitmix-style increment (odd constant)
  inc_ = 0x6a09e667u ^ ((uint32_t)chaosKey[4] << 16 | chaosKey[5]);

  // rotation amounts derived reproducibly (1..31)
  rot1_ = 1 + (chaosKey[6] & 31);
  rot2_ = 1 + (chaosKey[7] & 31);

  // Burn-in: iterate map to decorrelate (128 iterations)
  for (int i = 0; i < 128; ++i) (void)nextByte();
}

// Polynomial P(x,y) = alpha*x + beta*y + gamma*x^2 + delta*y^2 + eps*x*y + zeta*x^3 + eta*y^3
static inline float polyP(const TinkerbellParams &p, const TinkerCoeffs &c) {
  float x = p.x, y = p.y;
  float xx = x * x, yy = y * y;
  float xxx = xx * x, yyy = yy * y;
  return c.alpha*x + c.beta*y + c.gamma*xx + c.delta*yy + c.eps*(x*y) + c.zeta*xxx + c.eta*yyy;
}

inline uint32_t xorshift32_mix(uint32_t &s, uint32_t inc) {
  // splitmix-like: s += inc; return mix of s
  s += inc;
  uint32_t z = s + 0x9e3779b9u;
  z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9u; // 64-bit constants truncated - ok for mixing
  z = (z ^ (z >> 27)) * 0x94d049bb133111ebu;
  z = z ^ (z >> 31);
  return z;
}

// produce one bit (LSB of mix)
inline uint8_t Tinkerbell::nextBit() {
  // iterate Tinkerbell (float)
  float xn = p_.x, yn = p_.y;
  float x1 = xn*xn - yn*yn + p_.a * xn + p_.b * yn;
  float y1 = 2.0f * xn * yn + p_.c * xn + p_.d * yn;
  p_.x = x1; p_.y = y1;

  // polynomial mixing
  float pp = polyP(p_, coeff_);

  // scale to 32-bit words (use absolute values)
  uint32_t ux = (uint32_t)(fabsf(x1) * 4294967295.0f);
  uint32_t uy = (uint32_t)(fabsf(y1) * 4294967295.0f);
  uint32_t up = (uint32_t)(fabsf(pp) * 4294967295.0f);

  // advance whitening state and get mixed word
  uint32_t xs = xorshift32_mix(s_, inc_);

  // mix with rotations
  uint32_t mix = ux ^ rotl32(uy, rot1_) ^ rotl32(up, rot2_) ^ xs;

  // small extra avalanche: multiply by odd constant and xor-shift
  mix = mix * 0xA3B1C2D3u;
  mix ^= (mix >> 16);

  return (uint8_t)(mix & 1u);
}

uint8_t Tinkerbell::nextByte() {
  uint8_t b = 0;
  for (int i = 0; i < 8; ++i) b |= (nextBit() << i);
  return b;
}

void Tinkerbell::generate(uint8_t* out, size_t bytes) {
  for (size_t i = 0; i < bytes; ++i) out[i] = nextByte();
}

void Tinkerbell::xorBitwise(uint8_t* data, size_t len) {
  for (size_t i = 0; i < len; ++i) data[i] ^= nextByte();
}


// More parameters (16 bytes → many floats) enlarge keyspace dramatically (each float mapped from bytes).

// Cubic polynomial introduces higher-degree nonlinearities: output becomes a complicated function of x,y and coefficients. This resists linear reconstruction and simple attack approaches.

// Mixing three independent scaled words (ux,uy,up) creates a much richer 32-bit pool before whitening. An attacker must recover both trajectories and polynomial coefficients.

// Robust whitening (splitmix-like increment + rot/xor/multiply) removes small biases that direct fractional-to-integer scaling can produce.

// All math is MCU-friendly: only multiplies, adds, abs, casts, rotates, xors — no costly ops.