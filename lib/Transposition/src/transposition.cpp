// transposition.cpp  -- Deterministic enhanced transposition with keyed PRNG
// Uses a platform-stable splitmix64-based PRNG seeded from a 16-byte key.
// All randomness consumed in exactly the same order for Forward and Inverse modes,
// guaranteeing deterministic invertibility (same key -> same mapping).

#include "transposition.h"
#include "tinkerbell.h"   // kept for compatibility (not used in PRNG below)
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

// ---------------- DeterministicPRNG: splitmix64-based PRNG (platform-stable) ----------------
static inline uint64_t load64be(const uint8_t *p) {
  return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) | ((uint64_t)p[2] << 40) |
         ((uint64_t)p[3] << 32) | ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
         ((uint64_t)p[6] << 8)  | ((uint64_t)p[7]);
}

struct DeterministicPRNG {
  uint64_t state;
  explicit DeterministicPRNG(const uint8_t key16[16]) {
    uint64_t s0 = load64be(key16);
    uint64_t s1 = load64be(key16 + 8);
    state = s0 ^ (s1 + 0x9E3779B97F4A7C15ull);
    if (state == 0) state = 0xCAFEBABEDEADBEEFull;
  }
  uint64_t next64() {
    uint64_t z = (state += 0x9E3779B97F4A7C15ull);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
  }
  uint32_t next32() { return (uint32_t)(next64() & 0xFFFFFFFFu); }
  uint8_t nextByte() { return (uint8_t)(next64() & 0xFFu); }
};

// ---------------- existing helpers (unchanged) ----------------
struct BlockDim {
  size_t rows, cols;
  size_t r0, r1, c0, c1;  // actual coordinates in grid
};

static void readBlock(const uint8_t *data, const GridSpec &g, const BlockDim &block, uint8_t *tmpBuf) {
  size_t idx = 0;
  for (size_t r = block.r0; r < block.r1; ++r) {
    for (size_t c = block.c0; c < block.c1; ++c) {
      tmpBuf[idx++] = data[r * g.cols + c];
    }
  }
}

static void writeBlock(uint8_t *data, const GridSpec &g, const BlockDim &block, const uint8_t *tmpBuf) {
  size_t idx = 0;
  for (size_t r = block.r0; r < block.r1; ++r) {
    for (size_t c = block.c0; c < block.c1; ++c) {
      data[r * g.cols + c] = tmpBuf[idx++];
    }
  }
}

static void rotateRowInBlock(uint8_t *block, size_t blockCols, size_t rowIndex, int offset) {
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

static void rotateColInBlock(uint8_t *block, size_t blockCols, size_t blockRows, size_t colIndex, int offset) {
  if (blockRows == 0) return;
  offset = ((offset % (int)blockRows) + (int)blockRows) % (int)blockRows;
  if (offset == 0) return;
  uint8_t *tmp = (uint8_t*)malloc(blockRows);
  if (!tmp) return;
  for (size_t r = 0; r < blockRows; ++r) tmp[r] = block[r * blockCols + colIndex];
  for (size_t r = 0; r < blockRows; ++r) block[r * blockCols + colIndex] = tmp[(r + blockRows - offset) % blockRows];
  free(tmp);
}

// Fisher-Yates shuffle (uint16_t) using ChaoticPRNG
static void fy_shuffle_uint16(uint16_t *arr, size_t n, DeterministicPRNG &prng) {
  if (n <= 1) return;
  for (size_t i = n - 1; i > 0; --i) {
    uint32_t rnd32 = prng.next32();
    size_t j = (size_t)(rnd32 % (uint32_t)(i + 1));
    uint16_t tmp = arr[i];
    arr[i] = arr[j];
    arr[j] = tmp;
  }
}

// ---------------- Main enhanced transposition - now chaos-driven ----------------
void applyTranspositionEnhanced(uint8_t *data, const GridSpec &grid, const uint8_t key[16], PermuteMode mode) {
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

  // Use DeterministicPRNG seeded with the 16-byte key
  DeterministicPRNG prng(key);

  // Pre-calc block dims for every original block index
  BlockDim *blockDims = (BlockDim*)malloc(sizeof(BlockDim) * totalBlocks);
  if (!blockDims) return;
  for (size_t b = 0; b < totalBlocks; ++b) {
    size_t brIdx = b / bc;
    size_t bcIdx = b % bc;
    blockDims[b].r0 = brIdx * blockH;
    blockDims[b].c0 = bcIdx * blockW;
    blockDims[b].r1 = (blockDims[b].r0 + blockH) > grid.rows ? grid.rows : (blockDims[b].r0 + blockH);
    blockDims[b].c1 = (blockDims[b].c0 + blockW) > grid.cols ? grid.cols : (blockDims[b].c0 + blockW);
    blockDims[b].rows = blockDims[b].r1 - blockDims[b].r0;
    blockDims[b].cols = blockDims[b].c1 - blockDims[b].c0;
  }

  // Group blocks by (rows,cols) so we only permute within identical shapes (ensures invertibility)
  int *groupId = (int*)malloc(sizeof(int) * totalBlocks);
  if (!groupId) { free(blockDims); return; }
  for (size_t i = 0; i < totalBlocks; ++i) groupId[i] = -1;

  // store unique pairs
  size_t *grows = (size_t*)malloc(sizeof(size_t) * totalBlocks);
  size_t *gcols = (size_t*)malloc(sizeof(size_t) * totalBlocks);
  if (!grows || !gcols) { free(blockDims); free(groupId); free(grows); free(gcols); return; }
  size_t uniqueCount = 0;

  for (size_t b = 0; b < totalBlocks; ++b) {
    size_t rr = blockDims[b].rows;
    size_t cc = blockDims[b].cols;
    size_t k;
    for (k = 0; k < uniqueCount; ++k) {
      if (grows[k] == rr && gcols[k] == cc) {
        groupId[b] = (int)k;
        break;
      }
    }
    if (k == uniqueCount) {
      // new group
      grows[uniqueCount] = rr;
      gcols[uniqueCount] = cc;
      groupId[b] = (int)uniqueCount;
      uniqueCount++;
    }
  }

  // count group sizes
  size_t *groupCounts = (size_t*)calloc(uniqueCount, sizeof(size_t));
  if (!groupCounts) { free(blockDims); free(groupId); free(grows); free(gcols); return; }
  for (size_t b = 0; b < totalBlocks; ++b) groupCounts[groupId[b]]++;

  // prefix offsets and members list
  size_t *groupOffsets = (size_t*)malloc(sizeof(size_t) * (uniqueCount + 1));
  if (!groupOffsets) { free(blockDims); free(groupId); free(grows); free(gcols); free(groupCounts); return; }
  groupOffsets[0] = 0;
  for (size_t k = 0; k < uniqueCount; ++k) groupOffsets[k + 1] = groupOffsets[k] + groupCounts[k];

  uint16_t *members = (uint16_t*)malloc(sizeof(uint16_t) * totalBlocks);
  if (!members) { free(blockDims); free(groupId); free(grows); free(gcols); free(groupCounts); free(groupOffsets); return; }

  // temp cursor to fill members
  size_t *fillCursor = (size_t*)malloc(sizeof(size_t) * uniqueCount);
  if (!fillCursor) { free(blockDims); free(groupId); free(grows); free(gcols); free(groupCounts); free(groupOffsets); free(members); return; }
  for (size_t k = 0; k < uniqueCount; ++k) fillCursor[k] = groupOffsets[k];

  for (size_t b = 0; b < totalBlocks; ++b) {
    int gid = groupId[b];
    members[fillCursor[gid]++] = (uint16_t)b;
  }

  // Build blockIdx mapping (destination index -> source index), but only permute inside each group
  uint16_t *blockIdx = (uint16_t*)malloc(sizeof(uint16_t) * totalBlocks);
  if (!blockIdx) { free(blockDims); free(groupId); free(grows); free(gcols); free(groupCounts); free(groupOffsets); free(members); free(fillCursor); return; }

  for (size_t k = 0; k < uniqueCount; ++k) {
    size_t start = groupOffsets[k];
    size_t cnt = groupCounts[k];
    if (cnt == 0) continue;

    // copy members slice
    uint16_t *slice = (uint16_t*)malloc(sizeof(uint16_t) * cnt);
    if (!slice) { /* fallback: identity mapping for this group */ 
      for (size_t i = 0; i < cnt; ++i) blockIdx[members[start + i]] = members[start + i];
      continue;
    }
    for (size_t i = 0; i < cnt; ++i) slice[i] = members[start + i];

    // shuffle 'slice' using chaotic PRNG to obtain sources for destinations in 'members[start..]'
    fy_shuffle_uint16(slice, cnt, prng);

    // map: destination = members[start + i]  gets source = slice[i]
    for (size_t i = 0; i < cnt; ++i) {
      uint16_t dst = members[start + i];
      uint16_t src = slice[i];
      blockIdx[dst] = src;
    }
    free(slice);
  }

  // Build inverse mapping: inv[dst] = src such that dst <- src under forward mapping
  uint16_t *invBlockIdx = (uint16_t*)malloc(sizeof(uint16_t) * totalBlocks);
  if (!invBlockIdx) { free(blockIdx); free(blockDims); free(groupId); free(grows); free(gcols); free(groupCounts); free(groupOffsets); free(members); free(fillCursor); return; }
  for (size_t dst = 0; dst < totalBlocks; ++dst) {
    uint16_t src = blockIdx[dst];
    invBlockIdx[src] = (uint16_t)dst;
  }

  // Generate operations deterministically for each original block using chaotic PRNG
  struct BlockOp { uint8_t type; uint8_t p1; int8_t p2; };
  const size_t MAX_OPS_PER_BLOCK = 6;
  BlockOp *ops = (BlockOp*)malloc(sizeof(BlockOp) * totalBlocks * MAX_OPS_PER_BLOCK);
  if (!ops) { free(blockIdx); free(invBlockIdx); free(blockDims); free(groupId); free(grows); free(gcols); free(groupCounts); free(groupOffsets); free(members); free(fillCursor); return; }

  for (size_t b = 0; b < totalBlocks; ++b) {
    uint8_t opCount = 1 + (prng.nextByte() & 0x03);
    for (size_t o = 0; o < MAX_OPS_PER_BLOCK; ++o) {
      BlockOp &op = ops[b * MAX_OPS_PER_BLOCK + o];
      if (o < opCount) {
        uint8_t r1 = prng.nextByte();
        uint8_t r2 = prng.nextByte();
        op.type = r1 & 0x07;
        op.p1 = r2;
        op.p2 = (int8_t)(prng.nextByte() & 0x0F) - 8;
      } else {
        op.type = 0xFF;
      }
    }
  }

  // Helper apply ops on block by original block index
  auto applyOpsOnBlock = [&](uint8_t *buf, size_t blockRows, size_t blockCols, size_t origBlockIndex, bool forward) {
    if (!buf) return;
    size_t base = origBlockIndex * MAX_OPS_PER_BLOCK;
    if (forward) {
      for (size_t o = 0; o < MAX_OPS_PER_BLOCK; ++o) {
        BlockOp &op = ops[base + o];
        if (op.type == 0xFF) break;
        switch (op.type & 0x07) {
          case 0: {
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
          case 1: {
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
          case 2: {
            for (size_t rr = 0; rr < blockRows; ++rr) {
              size_t a = rr * blockCols;
              size_t b = a + blockCols - 1;
              for (; a < b; ++a, --b) {
                uint8_t t = buf[a]; buf[a] = buf[b]; buf[b] = t;
              }
            }
            break;
          }
          case 3: {
            for (size_t cc = 0; cc < blockCols; ++cc) {
              size_t a = cc;
              size_t b = (blockRows - 1) * blockCols + cc;
              for (; a < b; a += blockCols, b -= blockCols) {
                uint8_t t = buf[a]; buf[a] = buf[b]; buf[b] = t;
              }
            }
            break;
          }
          case 4: {
            int off = op.p2;
            for (size_t rr = 0; rr < blockRows; ++rr) rotateRowInBlock(buf, blockCols, rr, off);
            break;
          }
          case 5: {
            int off = op.p2;
            for (size_t cc = 0; cc < blockCols; ++cc) rotateColInBlock(buf, blockCols, blockRows, cc, off);
            break;
          }
          default: break;
        }
      }
    } else {
      for (int o = (int)MAX_OPS_PER_BLOCK - 1; o >= 0; --o) {
        BlockOp &op = ops[base + o];
        if (op.type == 0xFF) continue;
        uint8_t t = op.type & 0x07;
        switch (t) {
          case 0: {
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
          case 1: {
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
          case 2: {
            for (size_t rr = 0; rr < blockRows; ++rr) {
              size_t a = rr * blockCols;
              size_t b = a + blockCols - 1;
              for (; a < b; ++a, --b) {
                uint8_t tmp = buf[a]; buf[a] = buf[b]; buf[b] = tmp;
              }
            }
            break;
          }
          case 3: {
            for (size_t cc = 0; cc < blockCols; ++cc) {
              size_t a = cc;
              size_t b = (blockRows - 1) * blockCols + cc;
              for (; a < b; a += blockCols, b -= blockCols) {
                uint8_t tmp = buf[a]; buf[a] = buf[b]; buf[b] = tmp;
              }
            }
            break;
          }
          case 4: {
            int off = -op.p2;
            for (size_t rr = 0; rr < blockRows; ++rr) rotateRowInBlock(buf, blockCols, rr, off);
            break;
          }
          case 5: {
            int off = -op.p2;
            for (size_t cc = 0; cc < blockCols; ++cc) rotateColInBlock(buf, blockCols, blockRows, cc, off);
            break;
          }
          default: break;
        }
      }
    }
  };

  // tmp buffer sized to largest block in group (blockH * blockW is an upper bound)
  size_t maxBlockBytes = blockH * blockW ? (blockH * blockW) : 1;
  uint8_t *tmpBuf = (uint8_t*)malloc(maxBlockBytes);
  if (!tmpBuf) { /* cleanup */ free(blockIdx); free(invBlockIdx); free(ops); free(blockDims); free(groupId); free(grows); free(gcols); free(groupCounts); free(groupOffsets); free(members); free(fillCursor); return; }

  // src copy so reads are stable while we write into 'data'
  size_t totalBytes = grid.rows * grid.cols;
  uint8_t *srcCopy = (uint8_t*)malloc(totalBytes);
  if (!srcCopy) { free(tmpBuf); free(blockIdx); free(invBlockIdx); free(ops); free(blockDims); free(groupId); free(grows); free(gcols); free(groupCounts); free(groupOffsets); free(members); free(fillCursor); return; }
  memcpy(srcCopy, data, totalBytes);

  if (mode == PermuteMode::Forward) {
    for (size_t dstBlock = 0; dstBlock < totalBlocks; ++dstBlock) {
      uint16_t srcBlock = blockIdx[dstBlock]; // original block index that will be placed at dstBlock
      // read source block (original slot)
      readBlock(srcCopy, grid, blockDims[srcBlock], tmpBuf);
      // apply ops generated for srcBlock (forward)
      applyOpsOnBlock(tmpBuf, blockDims[srcBlock].rows, blockDims[srcBlock].cols, srcBlock, true);
      // write into dstBlock slot (same shape guaranteed by grouping)
      writeBlock(data, grid, blockDims[dstBlock], tmpBuf);
    }
  } else {
    // inverse: reconstruct original by placing each permuted destination block back to its source
    for (size_t dstBlock = 0; dstBlock < totalBlocks; ++dstBlock) {
      uint16_t srcBlock = invBlockIdx[dstBlock]; // original source index that ended up at dstBlock
      // read permuted data from dstBlock slot
      readBlock(srcCopy, grid, blockDims[dstBlock], tmpBuf);
      // apply inverse ops for original srcBlock (use the original shape parameters)
      applyOpsOnBlock(tmpBuf, blockDims[srcBlock].rows, blockDims[srcBlock].cols, srcBlock, false);
      // write back into original source slot
      writeBlock(data, grid, blockDims[srcBlock], tmpBuf);
    }
  }

  // cleanup
  free(tmpBuf);
  free(srcCopy);
  free(blockIdx);
  free(invBlockIdx);
  free(ops);
  free(blockDims);
  free(groupId);
  free(grows);
  free(gcols);
  free(groupCounts);
  free(groupOffsets);
  free(members);
  free(fillCursor);
}
  
// Public wrapper: accept 8-byte key and call enhanced implementation.
void applyTransposition(uint8_t *data, const GridSpec &grid, const uint8_t key[8], PermuteMode mode) {
  uint8_t key16[16];
  if (key) {
    memcpy(key16, key, 8);
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
