#include "tinkerbell.h"
#include <math.h>

double Tinkerbell::mapRange(uint8_t v, double lo, double hi) {
  const double t = (double)v / 255.0;
  return lo + t * (hi - lo);
}

double Tinkerbell::fracFrom16(uint8_t hi, uint8_t lo) {
  uint16_t u = ((uint16_t)hi << 8) | lo;
  double f = (double)(1 + u) / 65536.0; // (0,1]
  if (f >= 1.0) f = 0.999984741;
  return f;
}

Tinkerbell::Tinkerbell(const uint8_t chaosKey[8]) {
  p_.a = mapRange(chaosKey[0], -0.90, -0.50);
  p_.b = mapRange(chaosKey[1], -0.80, -0.40);
  p_.c = mapRange(chaosKey[2],  1.80,  2.20);
  p_.d = mapRange(chaosKey[3],  0.70,  1.10);
  p_.x = fracFrom16(chaosKey[4], chaosKey[5]);
  p_.y = fracFrom16(chaosKey[6], chaosKey[7]);

  // Seed whitening state with key bytes
  s_ = ((uint32_t)chaosKey[0] << 24) | ((uint32_t)chaosKey[1] << 16) |
       ((uint32_t)chaosKey[2] << 8)  | (uint32_t)chaosKey[3];
  if (s_ == 0) s_ = 0x9E3779B9u; // non-zero default

  // Burn-in iterations to decorrelate initial state
  for (int i = 0; i < 64; ++i) (void)nextBit();
}

uint8_t Tinkerbell::nextBit() {
  // Iterate
  double xn = p_.x, yn = p_.y;
  double x1 = xn*xn - yn*yn + p_.a * xn + p_.b * yn;
  double y1 = 2.0 * xn * yn + p_.c * xn + p_.d * yn;
  p_.x = x1; p_.y = y1;

  // Extract 32-bit words from x and y magnitudes
  double ax = fabs(x1), ay = fabs(y1);
  double sx = fmod(ax * 4294967296.0, 4294967296.0);
  double sy = fmod(ay * 4294967296.0, 4294967296.0);
  uint32_t ux = (uint32_t) (sx);
  uint32_t uy = (uint32_t) (sy);

  // Xorshift whitening state
  s_ ^= s_ << 13; s_ ^= s_ >> 17; s_ ^= s_ << 5;

  // Mix x, y, and the whitening state; take LSB as bit
  uint32_t mix = ux ^ rotl32(uy, 13) ^ s_;
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
