/**
 * transposition.h - Advanced transposition based on row/column swaps
 * - Grid is rows x cols (row-major)
 * - Swap sequence is derived from a secondary LFSR16 seeded with key bytes
 * - Supports forward (encrypt) and inverse (decrypt) permutations
 */
#pragma once
#include <stdint.h>
#include <stddef.h>

enum class PermuteMode
{
  Forward,
  Inverse
};

struct GridSpec
{
  size_t rows;
  size_t cols;
};

void applyTransposition(uint8_t *data, const GridSpec &grid, const uint8_t key[8], PermuteMode mode);
