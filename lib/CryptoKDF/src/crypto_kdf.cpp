#include "crypto_kdf.h"
#include <string.h>
#include <mbedtls/md.h>
#include <mbedtls/sha256.h>

static bool hmac_sha256(const uint8_t *key, size_t keyLen,
                        const uint8_t *data, size_t dataLen,
                        uint8_t out[32])
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
  if (mbedtls_md_hmac_finish(&ctx, out) != 0)
  {
    mbedtls_md_free(&ctx);
    return false;
  }
  mbedtls_md_free(&ctx);
  return true;
}

// RFC 8018 PBKDF2 with HMAC-SHA256
bool pbkdf2_sha256(const uint8_t *password, size_t passLen,
                   const uint8_t *salt, size_t saltLen,
                   uint32_t iterations,
                   uint8_t *out, size_t outLen)
{
  if (!password || !salt || !out || iterations == 0 || outLen == 0)
    return false;

  uint32_t blockCount = (outLen + 31) / 32;
  uint8_t U[32];
  uint8_t T[32];
  uint8_t *outPtr = out;
  size_t remaining = outLen;

  for (uint32_t block = 1; block <= blockCount; ++block)
  {
    // salt || INT_32_BE(block)
    uint8_t ibuf[64];
    if (saltLen + 4 > sizeof(ibuf))
      return false;
    memcpy(ibuf, salt, saltLen);
    ibuf[saltLen + 0] = (uint8_t)((block >> 24) & 0xFF);
    ibuf[saltLen + 1] = (uint8_t)((block >> 16) & 0xFF);
    ibuf[saltLen + 2] = (uint8_t)((block >> 8) & 0xFF);
    ibuf[saltLen + 3] = (uint8_t)(block & 0xFF);

    // U1 = HMAC(P, salt||block)
    if (!hmac_sha256(password, passLen, ibuf, saltLen + 4, U))
      return false;
    memcpy(T, U, 32);

    for (uint32_t i = 2; i <= iterations; ++i)
    {
      if (!hmac_sha256(password, passLen, U, 32, U))
        return false;
      for (int k = 0; k < 32; ++k)
        T[k] ^= U[k];
    }

    size_t toWrite = remaining < 32 ? remaining : 32;
    memcpy(outPtr, T, toWrite);
    outPtr += toWrite;
    remaining -= toWrite;
  }
  return true;
}

bool deriveKeys(const uint8_t *masterSecret, size_t masterLen, DerivedKeys &out)
{
  if (!masterSecret || masterLen < 32)
    return false;

  static const uint8_t salt[] = {
      // Protocol/version salt — do not change without bumping version
      'X', 'e', 'n', 'o', 'C', 'i', 'p', 'h', 'e', 'r', '-', 'K', 'D', 'F', '-', 'v', '1'};
  uint8_t buf[64] = {0};
  if (!pbkdf2_sha256(masterSecret, masterLen, salt, sizeof(salt), 1000, buf, sizeof(buf)))
  {
    return false;
  }

  // Split deterministically
  out.lfsrSeed = (uint16_t)((buf[0] << 8) | buf[1]); // 2 bytes
  memcpy(out.tinkerbellKey, buf + 2, 8);             // 8 bytes
  memcpy(out.transpositionKey, buf + 10, 8);         // 8 bytes
  memcpy(out.hmacKey, buf + 18, 32);                 // 32 bytes
  // Remaining bytes reserved for future
  // Ensure seed is non-zero
  if (out.lfsrSeed == 0)
    out.lfsrSeed = 0xACE1u;
  return true;
}
