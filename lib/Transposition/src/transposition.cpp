#include "transposition.h"
#include "../../LFSR/include/lfsr.h"
#include <string.h>

static inline void swapRows(uint8_t *data, const GridSpec &g, size_t r1, size_t r2)
{
  if (r1 == r2 || r1 >= g.rows || r2 >= g.rows)
    return;
  for (size_t c = 0; c < g.cols; ++c)
  {
    size_t i1 = r1 * g.cols + c;
    size_t i2 = r2 * g.cols + c;
    uint8_t tmp = data[i1];
    data[i1] = data[i2];
    data[i2] = tmp;
  }
}

static inline void swapCols(uint8_t *data, const GridSpec &g, size_t c1, size_t c2)
{
  if (c1 == c2 || c1 >= g.cols || c2 >= g.cols)
    return;
  for (size_t r = 0; r < g.rows; ++r)
  {
    size_t i1 = r * g.cols + c1;
    size_t i2 = r * g.cols + c2;
    uint8_t tmp = data[i1];
    data[i1] = data[i2];
    data[i2] = tmp;
  }
}

void applyTransposition(uint8_t *data, const GridSpec &grid, const uint8_t key[8], PermuteMode mode)
{
  // Secondary LFSR for permutations
  uint16_t seed = (uint16_t)((key[0] << 8) | key[1]);
  if (seed == 0)
    seed = 0xC481;
  // We can reuse the same taps by default; you can make this independent if desired
  LFSR16 lfsr(seed, 0x0029);

  // Decide how many swaps: heuristic based on grid size
  // For 4x3: 6 swaps (2 rows + 4 cols) — matches blueprint
  // For 4x8: 12 swaps — matches blueprint
  size_t rowSwaps = grid.rows + (grid.rows > 2 ? 1 : 0);
  size_t colSwaps = grid.cols + (grid.cols > 4 ? 2 : 0);

  const size_t totalOps = rowSwaps + colSwaps;

  // Generate operations sequence; to support inversion we must record the pairs.
  struct Op
  {
    bool isRow;
    uint8_t a, b;
  };
  Op *ops = new Op[totalOps];

  size_t idx = 0;
  for (size_t i = 0; i < rowSwaps; ++i)
  {
    uint8_t w = lfsr.nextByte();
    uint8_t a = w & 0x03; // 0..3 typical, fits 4 rows
    uint8_t b = (w >> 2) & 0x03;
    if (a >= grid.rows)
      a %= grid.rows;
    if (b >= grid.rows)
      b %= grid.rows;
    if (a == b)
      b = (b + 1) % grid.rows;
    ops[idx++] = {true, a, b};
  }
  for (size_t i = 0; i < colSwaps; ++i)
  {
    uint8_t w = lfsr.nextByte();
    uint8_t a = w % grid.cols;
    uint8_t b = (w / grid.cols) % grid.cols;
    if (a == b)
      b = (b + 1) % grid.cols;
    ops[idx++] = {false, a, b};
  }

  if (mode == PermuteMode::Forward)
  {
    for (size_t i = 0; i < totalOps; ++i)
    {
      if (ops[i].isRow)
        swapRows(data, grid, ops[i].a, ops[i].b);
      else
        swapCols(data, grid, ops[i].a, ops[i].b);
    }
  }
  else
  {
    // Inverse: apply in reverse order (swapping same indices undoes the op)
    for (size_t i = totalOps; i-- > 0;)
    {
      if (ops[i].isRow)
        swapRows(data, grid, ops[i].a, ops[i].b);
      else
        swapCols(data, grid, ops[i].a, ops[i].b);
    }
  }

  delete[] ops;
}
