#pragma once
#include <stdint.h>
#include <stddef.h>

// Permutation mode
enum class PermuteMode { Forward, Inverse };

// Grid dimensions for transposition
struct GridSpec {
    size_t rows;
    size_t cols;
};

/**
 * Standard transposition interface
 * - key: 8 bytes (will be expanded internally to 16 bytes via simple KDF)
 * - mode: Forward or Inverse permutation
 * - grid: specifies the block layout
 */
void applyTransposition(uint8_t *data, const GridSpec &grid, const uint8_t key[8], PermuteMode mode);
