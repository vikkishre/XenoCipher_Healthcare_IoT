#include "tinkerbell.h"
#include <math.h>

double Tinkerbell::mapRange(uint8_t v, double lo, double hi)
{
  const double t = (double)v / 255.0;
  return lo + t * (hi - lo);
}

double Tinkerbell::fracFrom16(uint8_t hi, uint8_t lo)
{
  uint32_t u = ((uint32_t)hi << 16) | ((uint32_t)lo << 8); // pack with spacing to avoid tiny ends
  // Map to (0,1) excluding exact 0 and 1
  double f = (double)(1 + ((hi << 8) | lo)) / 65536.0;
  if (f <= 0.0)
    f = 0.000015259; // ~1/65536
  if (f >= 1.0)
    f = 0.999984741;
  return f;
}

Tinkerbell::Tinkerbell(const uint8_t chaosKey[8])
{
  // Parameters in chaotic regime
  p_.a = mapRange(chaosKey[0], -0.90, -0.50);
  p_.b = mapRange(chaosKey[1], -0.80, -0.40);
  p_.c = mapRange(chaosKey[2], 1.80, 2.20);
  p_.d = mapRange(chaosKey[3], 0.70, 1.10);
  p_.x = fracFrom16(chaosKey[4], chaosKey[5]);
  p_.y = fracFrom16(chaosKey[6], chaosKey[7]);
  // Small burn-in to de-correlate from initial state (optional)
  for (int i = 0; i < 32; ++i)
    (void)nextBit();
}

uint8_t Tinkerbell::nextBit()
{
  // Iterate map
  double xn = p_.x, yn = p_.y;
  double x1 = xn * xn - yn * yn + p_.a * xn + p_.b * yn;
  double y1 = 2.0 * xn * yn + p_.c * xn + p_.d * yn;
  p_.x = x1;
  p_.y = y1;

  // Scale and extract one bit
  double scaled = x1 * 4294967296.0; // 2^32
  if (!isfinite(scaled))
    scaled = 0.0;
  uint32_t s = (uint32_t)llround(fmod(fabs(scaled), 4294967296.0));
  return (uint8_t)(s & 1u);
}

void Tinkerbell::generate(uint8_t *out, size_t bytes)
{
  for (size_t i = 0; i < bytes; ++i)
  {
    uint8_t b = 0;
    for (int bit = 0; bit < 8; ++bit)
    {
      b |= (nextBit() << bit);
    }
    out[i] = b;
  }
}

void Tinkerbell::xorBitwise(uint8_t *data, size_t len)
{
  for (size_t i = 0; i < len; ++i)
  {
    uint8_t ks = 0;
    for (int bit = 0; bit < 8; ++bit)
      ks |= (nextBit() << bit);
    data[i] ^= ks;
  }
}
