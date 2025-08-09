/**
 * hmac.h - HMAC-SHA256 utilities (with truncation)
 */
#pragma once
#include <stdint.h>
#include <stddef.h>

bool hmac_sha256_full(const uint8_t *key, size_t keyLen,
                      const uint8_t *data, size_t dataLen,
                      uint8_t out32[32]);

// Truncate to 'outLen' bytes (e.g., 8)
bool hmac_sha256_trunc(const uint8_t *key, size_t keyLen,
                       const uint8_t *data, size_t dataLen,
                       uint8_t *out, size_t outLen);
