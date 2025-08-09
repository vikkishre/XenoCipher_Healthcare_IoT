/**
 * crypto_kdf.h - PBKDF2-HMAC-SHA256 based deterministic key derivation
 * Derives:
 *  - LFSR seed (2 bytes)
 *  - Tinkerbell key (8 bytes)
 *  - Transposition key (8 bytes)
 *  - HMAC key (32 bytes)
 */
#pragma once
#include <stdint.h>
#include <stddef.h>

struct DerivedKeys
{
  uint16_t lfsrSeed;
  uint8_t tinkerbellKey[8];
  uint8_t transpositionKey[8];
  uint8_t hmacKey[32];
};

bool pbkdf2_sha256(const uint8_t *password, size_t passLen,
                   const uint8_t *salt, size_t saltLen,
                   uint32_t iterations,
                   uint8_t *out, size_t outLen);

/**
 * deriveKeys: deterministic split from a 64-byte master secret.
 * salt/context is fixed for this protocol version to ensure both sides match.
 */
bool deriveKeys(const uint8_t *masterSecret, size_t masterLen, DerivedKeys &out);
