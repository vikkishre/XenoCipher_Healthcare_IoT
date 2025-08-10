// transposition.cpp
// Deterministic enhanced transposition using a keyed splitmix64 PRNG.
// - Keeps public wrapper applyTransposition(key[8]) which expands to 16 bytes.
// - applyTranspositionEnhanced(data, grid, key16, mode) is the worker.
// - Uses dynamic buffers and robust bounds checks.

#include "transposition.h"
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

// Simple keyed PRNG using splitmix64 for deterministic keyed randomness.
struct KeyedPRNG {
  uint64_t s;
  KeyedPRNG(const uint8_t key16[16]) {
    // Combine key bytes into a 64-bit seed deterministically.
    uint64_t a = 0, b = 0;
    if (key16) {
      for (int i = 0; i < 8; ++i) a = (a << 8) | (uint64_t)key16[i];
      for (int i = 0; i < 8; ++i) b = (b << 8) | (uint64_t)key16[8 + i];
    }
    // Mix them; avoid zero state.
    s = a ^ ((b << 1) | (b >> 63)) ^ 0x9E3779B97F4A7C15ULL;
    if (s == 0) s = 0xDEADBEEFC0FFEEULL;
  }
  // splitmix64 next
  uint64_t next64() {
    uint64_t z = (s += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
  }
  uint32_t next32() { return (uint32_t)(next64() & 0xFFFFFFFFu); }
  uint8_t nextByte() { return (uint8_t)(next32() & 0xFFu); }
};

// Utility rotate (not used now but left if needed)
static inline uint32_t rotl32(uint32_t x, int r) { return (x << r) | (x >> (32 - r)); }

// Helper: read block (r0..r1-1, c0..c1-1) into tmpBuf (row-major)
static void readBlock(const uint8_t *data, const GridSpec &g,
                      size_t r0, size_t r1, size_t c0, size_t c1,
                      uint8_t *tmpBuf)
{
  size_t idx = 0;
  for (size_t r = r0; r < r1; ++r) {
    for (size_t c = c0; c < c1; ++c) {
      tmpBuf[idx++] = data[r * g.cols + c];
    }
  }
}

// Helper: writeBlock from tmpBuf back into data
static void writeBlock(uint8_t *data, const GridSpec &g,
                       size_t r0, size_t r1, size_t c0, size_t c1,
                       const uint8_t *tmpBuf)
{
  size_t idx = 0;
  for (size_t r = r0; r < r1; ++r) {
    for (size_t c = c0; c < c1; ++c) {
      data[r * g.cols + c] = tmpBuf[idx++];
    }
  }
}

// In-place row rotate in a block: shift row by offset mod width
static void rotateRowInBlock(uint8_t *block, size_t blockCols, size_t rowIndex, int offset)
{
  if (blockCols == 0) return;
  offset = ((offset % (int)blockCols) + (int)blockCols) % (int)blockCols;
  if (offset == 0) return;
  uint8_t *tmp = (uint8_t*)malloc(blockCols);
  if (!tmp) return;
  memcpy(tmp, block + rowIndex * blockCols, blockCols);
  for (size_t c = 0; c < blockCols; ++c) {
    block[rowIndex * blockCols + c] = tmp[(c + blockCols - offset) % blockCols];
  }
  free(tmp);
}

// In-place column rotate in a block
static void rotateColInBlock(uint8_t *block, size_t blockCols, size_t blockRows, size_t colIndex, int offset)
{
  if (blockRows == 0) return;
  offset = ((offset % (int)blockRows) + (int)blockRows) % (int)blockRows;
  if (offset == 0) return;
  uint8_t *tmp = (uint8_t*)malloc(blockRows);
  if (!tmp) return;
  for (size_t r = 0; r < blockRows; ++r) tmp[r] = block[r * blockCols + colIndex];
  for (size_t r = 0; r < blockRows; ++r) block[r * blockCols + colIndex] = tmp[(r + blockRows - offset) % blockRows];
  free(tmp);
}

// Fisher-Yates shuffle of array 'arr' of length n using KeyedPRNG
static void fy_shuffle_uint16(uint16_t *arr, size_t n, KeyedPRNG &prng)
{
  if (n <= 1) return;
  for (size_t i = n - 1; i > 0; --i) {
    uint32_t rnd32 = prng.next32();
    size_t j = (size_t)(rnd32 % (uint32_t)(i + 1));
    uint16_t tmp = arr[i];
    arr[i] = arr[j];
    arr[j] = tmp;
  }
}

// Main enhanced transposition
void applyTranspositionEnhanced(uint8_t *data, const GridSpec &grid, const uint8_t key[16], PermuteMode mode)
{
  if (!data || grid.rows == 0 || grid.cols == 0) return;

  // Determine block size heuristically from key (1..4)
  uint8_t hint = key ? key[0] : 0;
  size_t blockH = 1 + (hint % 4);
  size_t blockW = 1 + ((key ? key[1] : 0) % 4);

  if (blockH > grid.rows) blockH = grid.rows;
  if (blockW > grid.cols) blockW = grid.cols;

  size_t br = (grid.rows + blockH - 1) / blockH;
  size_t bc = (grid.cols + blockW - 1) / blockW;
  size_t totalBlocks = br * bc;
  if (totalBlocks == 0) return;

  // Keyed deterministic PRNG
  KeyedPRNG prng(key);

  // Build block index array
  uint16_t *blockIdx = (uint16_t*)malloc(sizeof(uint16_t) * totalBlocks);
  if (!blockIdx) return;
  for (uint16_t i = 0; i < (uint16_t)totalBlocks; ++i) blockIdx[i] = i;

  // Permute blockIdx deterministically
  fy_shuffle_uint16(blockIdx, totalBlocks, prng);

  // If decrypt mode, build inverse map
  uint16_t *invBlockIdx = NULL;
  if (mode == PermuteMode::Inverse) {
    invBlockIdx = (uint16_t*)malloc(sizeof(uint16_t) * totalBlocks);
    if (!invBlockIdx) { free(blockIdx); return; }
    // initialize (not strictly necessary but safe)
    for (size_t i = 0; i < totalBlocks; ++i) invBlockIdx[i] = 0xFFFF;
    for (size_t i = 0; i < totalBlocks; ++i) invBlockIdx[blockIdx[i]] = (uint16_t)i;
  }

  // temp buffer for one block (largest possible)
  size_t maxBlockRows = blockH;
  size_t maxBlockCols = blockW;
  size_t maxBlockBytes = (maxBlockRows == 0 || maxBlockCols == 0) ? 1 : (maxBlockRows * maxBlockCols);
  uint8_t *tmpBuf = (uint8_t*)malloc(maxBlockBytes);
  if (!tmpBuf) { free(blockIdx); if (invBlockIdx) free(invBlockIdx); return; }

  // Operation generation per block
  struct BlockOp { uint8_t type; uint8_t p1; int8_t p2; }; // type: 0=rowSwap,1=colSwap,2=rowRev,3=colRev,4=rowRot,5=colRot, 0xFF terminator
  const size_t MAX_OPS_PER_BLOCK = 6;
  BlockOp *ops = (BlockOp*)malloc(sizeof(BlockOp) * totalBlocks * MAX_OPS_PER_BLOCK);
  if (!ops) { free(blockIdx); if (invBlockIdx) free(invBlockIdx); free(tmpBuf); return; }

  // Fill ops deterministically using keyed PRNG
  for (size_t b = 0; b < totalBlocks; ++b) {
    uint8_t opCount = 1 + (prng.nextByte() & 0x03); // 1..4 ops
    for (size_t o = 0; o < MAX_OPS_PER_BLOCK; ++o) {
      BlockOp &op = ops[b * MAX_OPS_PER_BLOCK + o];
      if (o < opCount) {
        uint8_t r1 = prng.nextByte();
        uint8_t r2 = prng.nextByte();
        op.type = r1 & 0x07;
        op.p1 = r2;
        op.p2 = (int8_t)(prng.nextByte() & 0x0F) - 8; // rotation offset -8..7
      } else {
        op.type = 0xFF; // terminator
      }
    }
  }

  // Helper: apply ops directly on tmpBuf that contains blockRows x blockCols
  auto applyOpsOnTmpBuf = [&](uint8_t *buf, size_t blockRows, size_t blockCols, size_t blockIndex, PermuteMode modeLocal) {
    if (!buf) return;
    size_t base = blockIndex * MAX_OPS_PER_BLOCK;
    if (modeLocal == PermuteMode::Forward) {
      for (size_t o = 0; o < MAX_OPS_PER_BLOCK; ++o) {
        BlockOp &op = ops[base + o];
        if (op.type == 0xFF) break;
        switch (op.type & 0x07) {
          case 0: { // rowSwap
            if (blockRows <= 1) break;
            size_t a = op.p1 % blockRows;
            size_t b = (op.p1 ^ 0x55) % blockRows;
            if (a == b) b = (a + 1) % blockRows;
            for (size_t cc = 0; cc < blockCols; ++cc) {
              size_t i1 = a * blockCols + cc;
              size_t i2 = b * blockCols + cc;
              uint8_t t = buf[i1]; buf[i1] = buf[i2]; buf[i2] = t;
            }
            break;
          }
          case 1: { // colSwap
            if (blockCols <= 1) break;
            size_t a = op.p1 % blockCols;
            size_t b = (op.p1 ^ 0x33) % blockCols;
            if (a == b) b = (a + 1) % blockCols;
            for (size_t rr = 0; rr < blockRows; ++rr) {
              size_t i1 = rr * blockCols + a;
              size_t i2 = rr * blockCols + b;
              uint8_t t = buf[i1]; buf[i1] = buf[i2]; buf[i2] = t;
            }
            break;
          }
          case 2: { // rowReverse
            for (size_t rr = 0; rr < blockRows; ++rr) {
              size_t a = rr * blockCols;
              size_t b = a + blockCols - 1;
              for (; a < b; ++a, --b) {
                uint8_t t = buf[a]; buf[a] = buf[b]; buf[b] = t;
              }
            }
            break;
          }
          case 3: { // colReverse
            for (size_t cc = 0; cc < blockCols; ++cc) {
              size_t a = cc;
              size_t b = (blockRows - 1) * blockCols + cc;
              for (; a < b; a += blockCols, b -= blockCols) {
                uint8_t t = buf[a]; buf[a] = buf[b]; buf[b] = t;
              }
            }
            break;
          }
          case 4: { // rowRotate
            int off = op.p2;
            for (size_t rr = 0; rr < blockRows; ++rr) rotateRowInBlock(buf, blockCols, rr, off);
            break;
          }
          case 5: { // colRotate
            int off = op.p2;
            for (size_t cc = 0; cc < blockCols; ++cc) rotateColInBlock(buf, blockCols, blockRows, cc, off);
            break;
          }
          default: break;
        }
      }
    } else { // Inverse: reverse order, invert rotation sign
      for (int o = (int)MAX_OPS_PER_BLOCK - 1; o >= 0; --o) {
        BlockOp &op = ops[base + o];
        if (op.type == 0xFF) continue;
        uint8_t t = op.type & 0x07;
        switch (t) {
          case 0: { // rowSwap (self-inverse)
            if (blockRows <= 1) break;
            size_t a = op.p1 % blockRows;
            size_t b = (op.p1 ^ 0x55) % blockRows;
            if (a == b) b = (a + 1) % blockRows;
            for (size_t cc = 0; cc < blockCols; ++cc) {
              size_t i1 = a * blockCols + cc;
              size_t i2 = b * blockCols + cc;
              uint8_t tmp = buf[i1]; buf[i1] = buf[i2]; buf[i2] = tmp;
            }
            break;
          }
          case 1: { // colSwap
            if (blockCols <= 1) break;
            size_t a = op.p1 % blockCols;
            size_t b = (op.p1 ^ 0x33) % blockCols;
            if (a == b) b = (a + 1) % blockCols;
            for (size_t rr = 0; rr < blockRows; ++rr) {
              size_t i1 = rr * blockCols + a;
              size_t i2 = rr * blockCols + b;
              uint8_t tmp = buf[i1]; buf[i1] = buf[i2]; buf[i2] = tmp;
            }
            break;
          }
          case 2: { // rowReverse
            for (size_t rr = 0; rr < blockRows; ++rr) {
              size_t a = rr * blockCols;
              size_t b = a + blockCols - 1;
              for (; a < b; ++a, --b) {
                uint8_t tmp = buf[a]; buf[a] = buf[b]; buf[b] = tmp;
              }
            }
            break;
          }
          case 3: { // colReverse
            for (size_t cc = 0; cc < blockCols; ++cc) {
              size_t a = cc;
              size_t b = (blockRows - 1) * blockCols + cc;
              for (; a < b; a += blockCols, b -= blockCols) {
                uint8_t tmp = buf[a]; buf[a] = buf[b]; buf[b] = tmp;
              }
            }
            break;
          }
          case 4: { // rowRotate inverse: rotate by -p2
            int off = -op.p2;
            for (size_t rr = 0; rr < blockRows; ++rr) rotateRowInBlock(buf, blockCols, rr, off);
            break;
          }
          case 5: { // colRotate inverse
            int off = -op.p2;
            for (size_t cc = 0; cc < blockCols; ++cc) rotateColInBlock(buf, blockCols, blockRows, cc, off);
            break;
          }
          default: break;
        }
      }
    }
  }; // end applyOpsOnTmpBuf

  // Now apply block permutation + per-block ops
  if (mode == PermuteMode::Forward) {
    size_t totalBytes = grid.rows * grid.cols;
    uint8_t *srcCopy = (uint8_t*)malloc(totalBytes);
    if (!srcCopy) { free(blockIdx); if (invBlockIdx) free(invBlockIdx); free(tmpBuf); free(ops); return; }
    memcpy(srcCopy, data, totalBytes);

    for (size_t dstBlock = 0; dstBlock < totalBlocks; ++dstBlock) {
      uint16_t srcBlock = blockIdx[dstBlock];

      // compute src block coordinates
      size_t brIdx = srcBlock / bc;
      size_t bcIdx = srcBlock % bc;
      size_t r0 = brIdx * blockH;
      size_t c0 = bcIdx * blockW;
      size_t r1 = (r0 + blockH) > grid.rows ? grid.rows : (r0 + blockH);
      size_t c1 = (c0 + blockW) > grid.cols ? grid.cols : (c0 + blockW);
      size_t blockRows = r1 - r0;
      size_t blockCols = c1 - c0;

      // read src block into tmpBuf
      readBlock(srcCopy, grid, r0, r1, c0, c1, tmpBuf);

      // apply intra-block ops on tmpBuf (forward)
      applyOpsOnTmpBuf(tmpBuf, blockRows, blockCols, dstBlock, PermuteMode::Forward);

      // write into destination position in data
      size_t dbr = dstBlock / bc; size_t dbc = dstBlock % bc;
      size_t dr0 = dbr * blockH; size_t dc0 = dbc * blockW;
      size_t dr1 = (dr0 + blockH) > grid.rows ? grid.rows : (dr0 + blockH);
      size_t dc1 = (dc0 + blockW) > grid.cols ? grid.cols : (dc0 + blockW);

      writeBlock(data, grid, dr0, dr1, dc0, dc1, tmpBuf);
    }

    free(srcCopy);
  } else {
    // Inverse: read blocks from permuted positions, apply inverse ops and write to original
    size_t totalBytes = grid.rows * grid.cols;
    uint8_t *srcCopy = (uint8_t*)malloc(totalBytes);
    if (!srcCopy) { free(blockIdx); if (invBlockIdx) free(invBlockIdx); free(tmpBuf); free(ops); return; }
    memcpy(srcCopy, data, totalBytes);

    for (size_t srcBlock = 0; srcBlock < totalBlocks; ++srcBlock) {
      uint16_t permPos = invBlockIdx[srcBlock];

      size_t pr = permPos / bc; size_t pc = permPos % bc;
      size_t r0 = pr * blockH;
      size_t c0 = pc * blockW;
      size_t r1 = (r0 + blockH) > grid.rows ? grid.rows : (r0 + blockH);
      size_t c1 = (c0 + blockW) > grid.cols ? grid.cols : (c0 + blockW);
      size_t blockRows = r1 - r0;
      size_t blockCols = c1 - c0;

      // read permuted block from srcCopy into tmpBuf
      readBlock(srcCopy, grid, r0, r1, c0, c1, tmpBuf);

      // apply inverse ops for that block index (permPos)
      applyOpsOnTmpBuf(tmpBuf, blockRows, blockCols, permPos, PermuteMode::Inverse);

      // write back to original (srcBlock) position in data
      size_t dbr = srcBlock / bc; size_t dbc = srcBlock % bc;
      size_t dr0 = dbr * blockH; size_t dc0 = dbc * blockW;
      size_t dr1 = (dr0 + blockH) > grid.rows ? grid.rows : (dr0 + blockH);
      size_t dc1 = (dc0 + blockW) > grid.cols ? grid.cols : (dc0 + blockW);

      writeBlock(data, grid, dr0, dr1, dc0, dc1, tmpBuf);
    }

    free(srcCopy);
  }

  // cleanup
  free(blockIdx);
  if (invBlockIdx) free(invBlockIdx);
  free(tmpBuf);
  free(ops);
}

// ---------------------------------------------------------------------------
// Public wrapper: accept 8-byte key and call enhanced implementation.
// If caller already has 16-byte key, they can call applyTranspositionEnhanced directly.
// ---------------------------------------------------------------------------
void applyTransposition(uint8_t *data, const GridSpec &grid, const uint8_t key[8], PermuteMode mode)
{
  uint8_t key16[16];
  if (key) {
    memcpy(key16, key, 8);
    // Expand simple deterministic way to 16 bytes (not cryptographic KDF but deterministic)
    for (int i = 0; i < 8; ++i) {
      uint8_t a = key[i];
      uint8_t b = key[(i + 3) & 7];
      key16[8 + i] = (uint8_t)(((a << 3) | (a >> 5)) ^ ((b << 1) | (b >> 7)) ^ 0xA5u ^ (uint8_t)i);
    }
  } else {
    memset(key16, 0, sizeof(key16));
  }
  applyTranspositionEnhanced(data, grid, key16, mode);
}
