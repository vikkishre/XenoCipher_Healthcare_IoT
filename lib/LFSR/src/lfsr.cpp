#include "lfsr.h"
#include <string.h>
#include "hmac.h"

// Efficient parity calculation for 32-bit
static inline uint8_t parity32(uint32_t x) {
    x ^= x >> 16;
    x ^= x >> 8;
    x ^= x >> 4;
    x ^= x >> 2;
    x ^= x >> 1;
    return x & 1;
}

// Deterministic HMAC-based keystream (same as used for Tinkerbell replacement)
static void hmac_stream_block(const uint8_t key16[16], uint32_t seedBe, uint32_t counter, uint8_t out32[32]) {
    const char label[] = "XENO-LFSR";
    uint8_t msg[sizeof(label) + 4 + 4];
    memcpy(msg, label, sizeof(label));
    msg[sizeof(label) + 0] = (uint8_t)((seedBe >> 24) & 0xFF);
    msg[sizeof(label) + 1] = (uint8_t)((seedBe >> 16) & 0xFF);
    msg[sizeof(label) + 2] = (uint8_t)((seedBe >> 8) & 0xFF);
    msg[sizeof(label) + 3] = (uint8_t)(seedBe & 0xFF);
    msg[sizeof(label) + 4] = (uint8_t)((counter >> 24) & 0xFF);
    msg[sizeof(label) + 5] = (uint8_t)((counter >> 16) & 0xFF);
    msg[sizeof(label) + 6] = (uint8_t)((counter >> 8) & 0xFF);
    msg[sizeof(label) + 7] = (uint8_t)(counter & 0xFF);
    hmac_sha256_full(key16, 16, msg, sizeof(msg), out32);
}

ChaoticLFSR32::ChaoticLFSR32(uint32_t seed, const uint8_t chaosKey16[16], uint32_t initialTap)
  : state_(seed ? seed : 0xACE1u), taps_(initialTap ? initialTap : 0xA3000001u), byteCounter_(0),
    blockIndex_(32), blockCounter_(0)
{
    memcpy(key16_, chaosKey16, 16);
    seedBe_ = ((seed >> 24) & 0xFF) | ((seed >> 8) & 0xFF00) | ((seed << 8) & 0xFF0000) | ((seed << 24) & 0xFF000000);
}

uint8_t ChaoticLFSR32::nextKeystreamByte() {
    if (blockIndex_ >= 32) {
        hmac_stream_block(key16_, seedBe_, blockCounter_++, block_);
        blockIndex_ = 0;
    }
    return block_[blockIndex_++];
}

uint32_t ChaoticLFSR32::generateTapMaskFromChaos() {
    uint32_t m = 0;
    for (int i = 0; i < 4; ++i) {
        m = (m << 8) | nextKeystreamByte();
    }
    m |= 1u;
    byteCounter_++;
    return m;
}


