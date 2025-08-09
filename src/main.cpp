/**
 * XenoCipher Healthcare IoT - Component-wise Pipeline Test
 * Layers: LFSR (byte XOR) -> Tinkerbell (bit XOR) -> Transposition -> HMAC(8)
 *
 * What to test:
 *  - Toggle grid sizes (4x3 for 12B, 4x8 for 32B)
 *  - Verify encrypt -> decrypt returns original
 *  - Validate printed intermediate values
 */
#include <Arduino.h>
#include <vector>

#include "crypto_kdf.h"
#include "lfsr.h"
#include "tinkerbell.h"
#include "transposition.h"
#include "hmac.h"

// Helpers
static void hexPrint(const char *label, const uint8_t *data, size_t n)
{
  Serial.printf("%s (%u): ", label, (unsigned)n);
  for (size_t i = 0; i < n; ++i)
  {
    Serial.printf("%02X", data[i]);
    if ((i + 1) % 16 == 0)
      Serial.print(" ");
  }
  Serial.println();
}

static std::vector<uint8_t> padToGrid(const uint8_t *in, size_t len, const GridSpec &g)
{
  const size_t need = g.rows * g.cols;
  std::vector<uint8_t> out(need, 0x00);
  memcpy(out.data(), in, len);
  return out;
}

static void pipelineEncrypt(const DerivedKeys &keys,
                            const uint8_t *plain, size_t plainLen,
                            const GridSpec &grid,
                            std::vector<uint8_t> &ciphertext,
                            uint8_t mac8[8])
{
  // Step 1: Pad
  std::vector<uint8_t> buf = padToGrid(plain, plainLen, grid);
  hexPrint("Plain (padded)", buf.data(), buf.size());

  // Step 2: LFSR XOR (byte-wise)
  {
    LFSR16 lfsr(keys.lfsrSeed, 0x0029); // taps for x^16 + x^5 + x^3 + 1
    std::vector<uint8_t> ks(buf.size());
    lfsr.generate(ks.data(), ks.size());
    hexPrint("LFSR keystream", ks.data(), ks.size());
    for (size_t i = 0; i < buf.size(); ++i)
      buf[i] ^= ks[i];
    hexPrint("After LFSR", buf.data(), buf.size());
  }

  // Step 3: Tinkerbell XOR (bit-wise)
  {
    Tinkerbell tk(keys.tinkerbellKey);
    tk.xorBitwise(buf.data(), buf.size());
    hexPrint("After Tinkerbell", buf.data(), buf.size());
  }

  // Step 4: Advanced Transposition (row/col swaps)
  {
    applyTransposition(buf.data(), grid, keys.transpositionKey, PermuteMode::Forward);
    hexPrint("After Transposition", buf.data(), buf.size());
  }

  // Step 5: HMAC-SHA256 truncated to 8 bytes
  if (!hmac_sha256_trunc(keys.hmacKey, sizeof(keys.hmacKey), buf.data(), buf.size(), mac8, 8))
  {
    memset(mac8, 0, 8);
  }

  ciphertext = std::move(buf);
}

static bool pipelineDecrypt(const DerivedKeys &keys,
                            const uint8_t *cipher, size_t cipherLen,
                            const GridSpec &grid,
                            const uint8_t mac8[8],
                            std::vector<uint8_t> &recovered)
{
  // Verify MAC first
  uint8_t mac_check[8];
  if (!hmac_sha256_trunc(keys.hmacKey, sizeof(keys.hmacKey), cipher, cipherLen, mac_check, 8))
  {
    return false;
  }
  if (memcmp(mac_check, mac8, 8) != 0)
  {
    Serial.println("MAC verification failed!");
    return false;
  }

  std::vector<uint8_t> buf(cipher, cipher + cipherLen);

  // Inverse steps:
  applyTransposition(buf.data(), grid, keys.transpositionKey, PermuteMode::Inverse);
  {
    Tinkerbell tk(keys.tinkerbellKey);
    tk.xorBitwise(buf.data(), buf.size()); // XOR again (self-inverse)
  }
  {
    LFSR16 lfsr(keys.lfsrSeed, 0x0029);
    std::vector<uint8_t> ks(buf.size());
    lfsr.generate(ks.data(), ks.size());
    for (size_t i = 0; i < buf.size(); ++i)
      buf[i] ^= ks[i];
  }

  recovered = std::move(buf);
  return true;
}

void setup()
{
  Serial.begin(115200);
  delay(1500);

  Serial.println("\n=== XenoCipher Component Pipeline (PlatformIO) ===");

  // Example master secret M (64 bytes). Replace with real post-NTRU shared secret.
  const uint8_t MASTER[64] = {
      0x60, 0xA1, 0xB2, 0x33, 0x44, 0x55, 0xC6, 0xD7, 0xE8, 0xF9, 0x0A, 0x1B, 0x2C, 0x3D, 0x4E, 0x5F,
      0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0x00,
      0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01,
      0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x0F, 0xED, 0xCB, 0xA9, 0x87, 0x65, 0x43, 0x21};

  DerivedKeys keys;
  if (!deriveKeys(MASTER, sizeof(MASTER), keys))
  {
    Serial.println("KDF failed!");
    while (true)
      delay(1000);
  }

  Serial.printf("LFSR seed: 0x%04X\n", keys.lfsrSeed);
  hexPrint("Tinkerbell key", keys.tinkerbellKey, 8);
  hexPrint("Transposition key", keys.transpositionKey, 8);

  // Example 1: "Xenocipher" (10 bytes) → 12 bytes (4x3)
  const char *msg1 = "Xenocipher";
  GridSpec grid12{4, 3};
  uint8_t mac1[8];
  std::vector<uint8_t> ct1;
  pipelineEncrypt(keys, (const uint8_t *)msg1, strlen(msg1), grid12, ct1, mac1);
  hexPrint("Ciphertext(12)", ct1.data(), ct1.size());
  hexPrint("HMAC-8", mac1, 8);

  std::vector<uint8_t> rec1;
  if (pipelineDecrypt(keys, ct1.data(), ct1.size(), grid12, mac1, rec1))
  {
    hexPrint("Recovered(12)", rec1.data(), rec1.size());
  }
  else
  {
    Serial.println("Decrypt 1 failed");
  }

  // Example 2: three health lines (30 bytes) → 32 bytes (4x8)
  const char *msg2 = "IR-112781\r\nBPM-7509\r\nAVG BPM-81"; // 30B
  GridSpec grid32{4, 8};
  uint8_t mac2[8];
  std::vector<uint8_t> ct2;
  pipelineEncrypt(keys, (const uint8_t *)msg2, strlen(msg2), grid32, ct2, mac2);
  hexPrint("Ciphertext(32)", ct2.data(), ct2.size());
  hexPrint("HMAC-8", mac2, 8);

  std::vector<uint8_t> rec2;
  if (pipelineDecrypt(keys, ct2.data(), ct2.size(), grid32, mac2, rec2))
  {
    hexPrint("Recovered(32)", rec2.data(), rec2.size());
  }
  else
  {
    Serial.println("Decrypt 2 failed");
  }

  Serial.println("\nReady. The loop prints uptime.");
}

void loop()
{
  static uint32_t last = 0;
  if (millis() - last > 2000)
  {
    last = millis();
    Serial.printf("Uptime %lus\n", millis() / 1000);
  }
}
