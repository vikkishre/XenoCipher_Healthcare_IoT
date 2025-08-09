#include "hmac.h"
#include <mbedtls/md.h>

bool hmac_sha256_full(const uint8_t *key, size_t keyLen,
                      const uint8_t *data, size_t dataLen,
                      uint8_t out32[32])
{
  const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if (!info)
    return false;
  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  if (mbedtls_md_setup(&ctx, info, 1) != 0)
  {
    mbedtls_md_free(&ctx);
    return false;
  }
  if (mbedtls_md_hmac_starts(&ctx, key, keyLen) != 0)
  {
    mbedtls_md_free(&ctx);
    return false;
  }
  if (mbedtls_md_hmac_update(&ctx, data, dataLen) != 0)
  {
    mbedtls_md_free(&ctx);
    return false;
  }
  if (mbedtls_md_hmac_finish(&ctx, out32) != 0)
  {
    mbedtls_md_free(&ctx);
    return false;
  }
  mbedtls_md_free(&ctx);
  return true;
}

bool hmac_sha256_trunc(const uint8_t *key, size_t keyLen,
                       const uint8_t *data, size_t dataLen,
                       uint8_t *out, size_t outLen)
{
  if (!out || outLen == 0 || outLen > 32)
    return false;
  uint8_t full[32];
  if (!hmac_sha256_full(key, keyLen, data, dataLen, full))
    return false;
  for (size_t i = 0; i < outLen; ++i)
    out[i] = full[i];
  return true;
}
