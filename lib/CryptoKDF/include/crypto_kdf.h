#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifndef KDF_ITERATIONS
// Not used by HKDF, but keep for compatibility if you want PBKDF2 fallback
#define KDF_ITERATIONS 5000
#endif

struct DerivedKeys {
  uint32_t lfsrSeed;           // 32-bit seed (non-zero)
  uint8_t  tinkerbellKey[16];  // chaos key (16 bytes)
  uint8_t  transpositionKey[16];// transposition key (16 bytes)
  uint8_t  hmacKey[32];        // MAC key (32 bytes)
};

struct MessageKeys {
  uint32_t lfsrSeed;
  uint8_t  tinkerbellKey[16];
  uint8_t  transpositionKey[16];
};

/**
 * HKDF-SHA256 extract/expand helpers and high-level derive functions
 */
bool hkdf_extract(const uint8_t *salt, size_t saltLen,
                  const uint8_t *ikm, size_t ikmLen,
                  uint8_t prk[32]);

bool hkdf_expand(const uint8_t prk[32],
                 const uint8_t *info, size_t infoLen,
                 uint8_t *out, size_t outLen);

/**
 * deriveKeys: derive base keys from masterSecret (32..64 bytes recommended)
 * Uses HKDF-Extract(protocol_salt, masterSecret) as PRK and HKDF-Expand with
 * domain-separated info strings.
 */
bool deriveKeys(const uint8_t* masterSecret, size_t masterLen, DerivedKeys& out);

/**
 * deriveMessageKeys: derive per-message keys deterministically (no XOR mixing).
 * Uses HKDF-Expand(PRK, "XENO-MSGK" || nonce_be32) where PRK is derived from base.hmacKey.
 *
 * Important: This function must produce independent per-message keys; caller must pass nonce.
 */
bool deriveMessageKeys(const DerivedKeys& base, uint32_t nonce, MessageKeys& out);
