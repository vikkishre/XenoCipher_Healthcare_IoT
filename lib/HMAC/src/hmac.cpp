#include "hmac.h"
#include <mbedtls/md.h>
#include <string.h>
#include <stdint.h>

// Secure zeroization helper (portable)
static void secure_memzero(void *v, size_t n) {
#if defined(__STDC_LIB_EXT1__)
  memset_s(v, n, 0, n);
#else
  volatile uint8_t *p = (volatile uint8_t *)v;
  while (n--) *p++ = 0;
#endif
}

// Constant-time compare. returns true if equal
static bool constant_time_eq(const uint8_t *a, const uint8_t *b, size_t n) {
  uint8_t diff = 0;
  for (size_t i = 0; i < n; ++i) diff |= a[i] ^ b[i];
  return diff == 0;
}

// Compute full 32-byte HMAC-SHA256 over a single contiguous buffer
bool hmac_sha256_full(const uint8_t *key, size_t keyLen,
                      const uint8_t *data, size_t dataLen,
                      uint8_t out32[32]) {
  if (!key || keyLen == 0 || !out32) return false;

  const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if (!info) return false;

  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);

  int rc = mbedtls_md_setup(&ctx, info, 1); // HMAC enabled
  if (rc != 0) { mbedtls_md_free(&ctx); return false; }

  rc = mbedtls_md_hmac_starts(&ctx, key, keyLen);
  if (rc != 0) { mbedtls_md_free(&ctx); return false; }

  if (data && dataLen) {
    rc = mbedtls_md_hmac_update(&ctx, data, dataLen);
    if (rc != 0) { mbedtls_md_free(&ctx); return false; }
  }

  rc = mbedtls_md_hmac_finish(&ctx, out32);
  mbedtls_md_free(&ctx);
  if (rc != 0) return false;

  return true;
}

// Compute full HMAC over multiple buffers (no concat)
bool hmac_sha256_multi(const uint8_t *key, size_t keyLen,
                       const uint8_t *const data[], const size_t dataLen[],
                       size_t numParts, uint8_t out32[32]) {
  if (!key || keyLen == 0 || !out32) return false;
  const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if (!info) return false;

  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);

  int rc = mbedtls_md_setup(&ctx, info, 1);
  if (rc != 0) { mbedtls_md_free(&ctx); return false; }

  rc = mbedtls_md_hmac_starts(&ctx, key, keyLen);
  if (rc != 0) { mbedtls_md_free(&ctx); return false; }

  for (size_t i = 0; i < numParts; ++i) {
    if (data[i] && dataLen[i]) {
      rc = mbedtls_md_hmac_update(&ctx, data[i], dataLen[i]);
      if (rc != 0) { mbedtls_md_free(&ctx); return false; }
    }
  }

  rc = mbedtls_md_hmac_finish(&ctx, out32);
  mbedtls_md_free(&ctx);
  if (rc != 0) return false;

  return true;
}

// Truncated HMAC convenience (computes full then truncates). Caller provides out buffer.
bool hmac_sha256_trunc(const uint8_t *key, size_t keyLen,
                       const uint8_t *data, size_t dataLen,
                       uint8_t *out, size_t outLen) {
  if (!out || outLen == 0 || outLen > 32) return false;
  uint8_t full[32];
  bool ok = hmac_sha256_full(key, keyLen, data, dataLen, full);
  if (!ok) return false;
  memcpy(out, full, outLen);
  secure_memzero(full, sizeof(full));
  return true;
}

// Constant-time verify over multiple buffers. macLen <= 32 (truncated)
bool hmac_sha256_verify(const uint8_t *key, size_t keyLen,
                        const uint8_t *const data[], const size_t dataLen[],
                        size_t numParts,
                        const uint8_t *mac, size_t macLen) {
  if (!mac || macLen == 0 || macLen > 32) return false;

  uint8_t full[32];
  bool ok = hmac_sha256_multi(key, keyLen, data, dataLen, numParts, full);
  if (!ok) return false;

  // constant-time compare only on macLen bytes
  bool eq = constant_time_eq(full, mac, macLen);
  secure_memzero(full, sizeof(full));
  return eq;
}
