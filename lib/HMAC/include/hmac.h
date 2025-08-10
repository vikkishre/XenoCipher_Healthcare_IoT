#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/*
 * HMAC-SHA256 safe utilities
 *
 *
 * Security Features:
 * - HMAC key length: 32 bytes (HKDF/SHA-256-derived)
 * - MAC truncation: 16 bytes recommended for IoT balance; 32 bytes for highest security
 * - Include counter/nonce in header and in HMAC (prevents replay/keystream reuse problems)
 * - Zero sensitive buffers after use (secure_memzero in implementation)
 * - Constant-time comparison for MAC verification
 *
 * Notes:
 * - Derive a separate hmac_key (32 bytes) from master key using HKDF/SHA256.
 * - Always include any metadata (header) in the MAC input.
 */

bool hmac_sha256_full(const uint8_t *key, size_t keyLen,
                      const uint8_t *data, size_t dataLen,
                      uint8_t out32[32]);

bool hmac_sha256_multi(const uint8_t *key, size_t keyLen,
                       const uint8_t *const data[], const size_t dataLen[],
                       size_t numParts, uint8_t out32[32]);

bool hmac_sha256_trunc(const uint8_t *key, size_t keyLen,
                       const uint8_t *data, size_t dataLen,
                       uint8_t *out, size_t outLen);

bool hmac_sha256_verify(const uint8_t *key, size_t keyLen,
                        const uint8_t *const data[], const size_t dataLen[],
                        size_t numParts,
                        const uint8_t *mac, size_t macLen);
