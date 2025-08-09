#include "lfsr.h"

static inline uint8_t parity16(uint16_t x)
{
  x ^= x >> 8;
  x ^= x >> 4;
  x ^= x >> 2;
  x ^= x >> 1;
  return x & 1;
}

LFSR16::LFSR16(uint16_t seed, uint16_t tapMask) : state_(seed ? seed : 1), taps_(tapMask) {}

void LFSR16::reseed(uint16_t seed) { state_ = seed ? seed : 1; }

uint8_t LFSR16::stepBit()
{
  // Output bit (before shift) — using LSB
  uint8_t out = (uint8_t)(state_ & 1u);
  // Feedback = parity of tapped bits
  uint8_t fb = parity16(state_ & taps_);
  // Shift right, insert feedback into MSB (bit 15)
  state_ = (uint16_t)((state_ >> 1) | (uint16_t)(fb << 15));
  return out;
}

uint8_t LFSR16::nextByte()
{
  uint8_t b = 0;
  for (int i = 0; i < 8; ++i)
  {
    b |= (stepBit() << i); // pack bits LSB-first
  }
  return b;
}

void LFSR16::generate(uint8_t *out, size_t n)
{
  for (size_t i = 0; i < n; ++i)
    out[i] = nextByte();
}

void LFSR16::xorBuffer(uint8_t *buf, size_t n)
{
  for (size_t i = 0; i < n; ++i)
    buf[i] ^= nextByte();
}
