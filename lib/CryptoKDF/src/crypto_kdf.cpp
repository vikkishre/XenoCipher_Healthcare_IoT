#include "../../../lib/common/common.h"
#include "crypto_kdf.h"
#include <string.h>
#include <mbedtls/md.h>
#include <mbedtls/platform_util.h> // for mbedtls_platform_zeroize if available
#include <stdint.h>
#include <stdlib.h>

// -----------------------------------------------------------------------------
// Helper: HMAC-SHA256 (wrapper)
// -----------------------------------------------------------------------------

// Returns boolean success/failure.
// out32 receives the 32-byte HMAC result.
// The function frees the mbedTLS context on failures too.

static bool hmac_sha256(const uint8_t* key, size_t keyLen,
                        const uint8_t* data, size_t dataLen,
                        uint8_t out32[32])
{
    const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!info) return false;
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    if (mbedtls_md_setup(&ctx, info, 1) != 0) { mbedtls_md_free(&ctx); return false; }
    if (mbedtls_md_hmac_starts(&ctx, key, keyLen) != 0) { mbedtls_md_free(&ctx); return false; }
    if (data && dataLen) {
        if (mbedtls_md_hmac_update(&ctx, data, dataLen) != 0) { mbedtls_md_free(&ctx); return false; }
    }
    if (mbedtls_md_hmac_finish(&ctx, out32) != 0) { mbedtls_md_free(&ctx); return false; }
    mbedtls_md_free(&ctx);
    return true;
}

// Secure zero helper
// To help Avoid leaving sensitive keys in memory after use
// Uses mbedtls_platform_zeroize if available, else a volatile pointer method 
static void secure_zero(void* p, size_t n) {
#if defined(mbedtls_platform_zeroize)
    mbedtls_platform_zeroize(p, n);
#else
    volatile uint8_t *q = (volatile uint8_t *)p;
    while (n--) *q++ = 0;
#endif
}

// -----------------------------------------------------------------------------
// HKDF Extract (PRK = HMAC(salt, IKM))
// If salt==NULL or saltLen==0, use a predefined common salt (lets use in addaptive switching)
// -----------------------------------------------------------------------------


bool hkdf_extract(const uint8_t *salt, size_t saltLen,
                  const uint8_t *ikm, size_t ikmLen,
                  uint8_t prk[32]) {
    if (!ikm || !prk) return false;

    const uint8_t* effectiveSalt = salt;
    size_t effectiveSaltLen = saltLen;

    if (!salt || saltLen == 0) {
        effectiveSalt = BACKUP_COMMON_SALT;
        effectiveSaltLen = sizeof(BACKUP_COMMON_SALT);
    }

    return hmac_sha256(effectiveSalt, effectiveSaltLen, ikm, ikmLen, prk);
}

// -----------------------------------------------------------------------------
// HKDF Expand - info-based expansion
// outLen must be <= 255*HashLen (we use SHA256, so large enough)
// -----------------------------------------------------------------------------
bool hkdf_expand(const uint8_t prk[32],
                 const uint8_t *info, size_t infoLen,
                 uint8_t *out, size_t outLen)
{
    if (!prk || !out || outLen == 0) return false;
    const size_t hashLen = 32;
    uint32_t n = (uint32_t)((outLen + hashLen - 1) / hashLen);
    if (n == 0 || n > 255) return false;

    uint8_t T[32];
    uint8_t previous[32];
    size_t produced = 0;
    uint8_t ctr = 1;

    memset(previous, 0, sizeof(previous));
    for (uint32_t i = 1; i <= n; ++i) {
        // data = previous || info || ctr
        // build data buffer in parts; use HMAC directly in sequence to avoid big buffer
        const mbedtls_md_info_t* info_md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
        if (!info_md) return false;
        mbedtls_md_context_t ctx;
        mbedtls_md_init(&ctx);
        if (mbedtls_md_setup(&ctx, info_md, 1) != 0) { mbedtls_md_free(&ctx); return false; }
        if (mbedtls_md_hmac_starts(&ctx, prk, 32) != 0) { mbedtls_md_free(&ctx); return false; }
        // previous
        if (i > 1) {
            if (mbedtls_md_hmac_update(&ctx, previous, hashLen) != 0) { mbedtls_md_free(&ctx); return false; }
        }
        // info
        if (info && infoLen) {
            if (mbedtls_md_hmac_update(&ctx, info, infoLen) != 0) { mbedtls_md_free(&ctx); return false; }
        }
        // ctr byte
        if (mbedtls_md_hmac_update(&ctx, &ctr, 1) != 0) { mbedtls_md_free(&ctx); return false; }
        if (mbedtls_md_hmac_finish(&ctx, T) != 0) { mbedtls_md_free(&ctx); return false; }
        mbedtls_md_free(&ctx);

        size_t copy = (produced + hashLen > outLen) ? (outLen - produced) : hashLen;
        memcpy(out + produced, T, copy);
        produced += copy;
        memcpy(previous, T, hashLen);
        ctr++;
    }

    // zero sensitive temporaries
    secure_zero(T, sizeof(T));
    secure_zero(previous, sizeof(previous));
    return true;
}

// -----------------------------------------------------------------------------
// High-level deriveKeys (HKDF-based)
// -----------------------------------------------------------------------------
bool deriveKeys(const uint8_t* masterSecret, size_t masterLen, DerivedKeys& out)
{
    if (!masterSecret || masterLen < 32) return false;

    // The master key is used directly for the encryption algorithms
    // The salt is now a shared secret and not derived from the master key
    
    // For the purpose of key derivation for the encryption algorithms, we can use a fixed info string
    const uint8_t info[] = { 'X','E','N','O','-','E','N','C','-','K','E','Y','S' };

    uint8_t prk[32];
    if (!hkdf_extract((const uint8_t*)COMMON_SALT, strlen(COMMON_SALT), masterSecret, masterLen, prk)) {
        return false;
    }

    // Expand separately for each subkey (domain separation via info)
    // 1) LFSR seed (4 bytes)
    {
        const uint8_t info[] = { 'X','E','N','O','-','L','F','S','R','-','S','E','E','D' }; // info label
        uint8_t outbuf[4];
        if (!hkdf_expand(prk, info, sizeof(info), outbuf, sizeof(outbuf))) { secure_zero(prk, sizeof(prk)); return false; }
        uint32_t seed = ((uint32_t)outbuf[0] << 24) | ((uint32_t)outbuf[1] << 16) | ((uint32_t)outbuf[2] << 8) | (uint32_t)outbuf[3];
        out.lfsrSeed = seed ? seed : 0xACE1u; // ensure non-zero
        secure_zero(outbuf, sizeof(outbuf));
    }

    // 2) Tinkerbell key (16 bytes)
    {
        const uint8_t info[] = { 'X','E','N','O','-','T','I','N','K','E','R','B','E','L','L','-','K' };
        if (!hkdf_expand(prk, info, sizeof(info), out.tinkerbellKey, sizeof(out.tinkerbellKey))) { secure_zero(prk, sizeof(prk)); return false; }
    }

    // 3) Transposition key (16 bytes)
    {
        const uint8_t info[] = { 'X','E','N','O','-','T','R','A','N','S','P','O','S','-','K' };
        if (!hkdf_expand(prk, info, sizeof(info), out.transpositionKey, sizeof(out.transpositionKey))) { secure_zero(prk, sizeof(prk)); return false; }
    }

    // 4) HMAC key (32 bytes)
    {
        const uint8_t info[] = { 'X','E','N','O','-','H','M','A','C','-','K','E','Y' };
        if (!hkdf_expand(prk, info, sizeof(info), out.hmacKey, sizeof(out.hmacKey))) { secure_zero(prk, sizeof(prk)); return false; }
    }

    // Zero PRK
    secure_zero(prk, sizeof(prk));
    return true;
}

// -----------------------------------------------------------------------------
// Per-message key derivation. Use base.hmacKey as PRK for message-specific expand.
// Info = "XENO-MSGK" || nonce_be32
// -----------------------------------------------------------------------------
bool deriveMessageKeys(const DerivedKeys& base, uint32_t nonce, MessageKeys& out)
{
    // PRK = HMAC(salt=none, IKM = base.hmacKey) => but HKDF-Extract with zero salt is HMAC(zero, IKM)
    // Simpler: use hkdf_extract with salt=NULL to produce prk via HMAC(zero, IKM)
    uint8_t prk[32];
    if (!hkdf_extract(NULL, 0, base.hmacKey, sizeof(base.hmacKey), prk)) return false;

    // Build info = label || nonce_be32
    uint8_t info[12];
    const char label[] = "XENO-MSGK"; // 8 bytes
    memcpy(info, label, 8);
    info[8] = (uint8_t)((nonce >> 24) & 0xFF);
    info[9] = (uint8_t)((nonce >> 16) & 0xFF);
    info[10] = (uint8_t)((nonce >> 8) & 0xFF);
    info[11] = (uint8_t)(nonce & 0xFF);

    // total bytes needed = 4 + 16 + 16 = 36
    uint8_t okm[36];
    if (!hkdf_expand(prk, info, sizeof(info), okm, sizeof(okm))) { secure_zero(prk, sizeof(prk)); return false; }

    // Fill out message keys (no XOR)
    uint32_t seed = ((uint32_t)okm[0] << 24) | ((uint32_t)okm[1] << 16) | ((uint32_t)okm[2] << 8) | (uint32_t)okm[3];
    out.lfsrSeed = seed ? seed : 0xACE1u;
    memcpy(out.tinkerbellKey, okm + 4, 16);
    memcpy(out.transpositionKey, okm + 20, 16);

    // wipe temporaries
    secure_zero(okm, sizeof(okm));
    secure_zero(prk, sizeof(prk));
    return true;
}
