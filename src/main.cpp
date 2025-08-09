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
#include <mbedtls/sha256.h>

#include "crypto_kdf.h"
#include "lfsr.h"
#include "tinkerbell.h"
#include "transposition.h"
#include "hmac.h"
#include "entropy.h"

// Helpers
static void hexPrint(const char* label, const uint8_t* data, size_t n) {
  Serial.printf("%s (%u): ", label, (unsigned)n);
  for (size_t i = 0; i < n; ++i) {
    Serial.printf("%02X", data[i]);
    if ((i+1) % 16 == 0) Serial.print(" ");
  }
  Serial.println();
}

static void asciiPrint(const char* label, const uint8_t* data, size_t n) {
  Serial.printf("%s (%u): ", label, (unsigned)n);
  for (size_t i = 0; i < n; ++i) {
    char c = (char)data[i];
    Serial.print(isprint((unsigned char)c) ? c : '.');
  }
  Serial.println();
}

struct SaltMeta {
  uint16_t pos;    // byte index where salt starts in original plaintext
  uint8_t  len;    // salt length in bytes
};

static std::vector<uint8_t> insertSalt(const uint8_t* plain, size_t plen,
                                       const uint8_t* salt, uint8_t slen,
                                       const SaltMeta& meta) {
  std::vector<uint8_t> out;
  out.reserve(plen + slen);
  uint16_t p = meta.pos > plen ? plen : meta.pos;
  out.insert(out.end(), plain, plain + p);
  out.insert(out.end(), salt, salt + slen);
  out.insert(out.end(), plain + p, plain + plen);
  return out;
}

static std::vector<uint8_t> removeSalt(const uint8_t* salted, size_t slenTotal,
                                       const SaltMeta& meta) {
  std::vector<uint8_t> out;
  if (meta.len == 0 || meta.pos > slenTotal) {
    out.assign(salted, salted + slenTotal);
    return out;
  }
  // salted length = original + salt.len
  size_t olen = slenTotal - meta.len;
  out.reserve(olen);
  out.insert(out.end(), salted, salted + meta.pos);
  out.insert(out.end(), salted + meta.pos + meta.len, salted + slenTotal);
  return out;
}

static std::vector<uint8_t> padToGrid(const uint8_t* in, size_t len, const GridSpec& g) {
  const size_t need = g.rows * g.cols;
  std::vector<uint8_t> out(need, 0x00);
  memcpy(out.data(), in, len);
  return out;
}

static GridSpec selectGrid(size_t len) {
  // Choose minimal of these: 4x3 (12), 4x8 (32), 8x8 (64)
  if (len <= 12) return GridSpec{4,3};
  if (len <= 32) return GridSpec{4,8};
  return GridSpec{8,8}; // extend as needed
}

static void pipelineEncrypt(const DerivedKeys& keys,
                            const uint8_t* plain, size_t plainLen,
                            const GridSpec& grid,
                            std::vector<uint8_t>& ciphertext,
                            uint8_t mac8[8],
                            bool verbose) {
  // Step 1: pad
  std::vector<uint8_t> buf = padToGrid(plain, plainLen, grid);
  if (verbose) hexPrint("Plain (padded)", buf.data(), buf.size());

  // Step 2: LFSR
  {
    LFSR16 lfsr(keys.lfsrSeed, 0x0029);
    std::vector<uint8_t> ks(buf.size());
    lfsr.generate(ks.data(), ks.size());
    if (verbose) hexPrint("LFSR keystream", ks.data(), ks.size());
    for (size_t i = 0; i < buf.size(); ++i) buf[i] ^= ks[i];
    if (verbose) hexPrint("After LFSR", buf.data(), buf.size());
  }

  // Step 3: Tinkerbell (bitwise/byte-pack)
  {
    Tinkerbell tk(keys.tinkerbellKey);
    tk.xorBitwise(buf.data(), buf.size());
    if (verbose) hexPrint("After Tinkerbell", buf.data(), buf.size());
  }

  // Step 4: Transposition
  {
    applyTransposition(buf.data(), grid, keys.transpositionKey, PermuteMode::Forward);
    if (verbose) hexPrint("After Transposition", buf.data(), buf.size());
  }

  // Step 5: HMAC-8 (over ciphertext)
  if (!hmac_sha256_trunc(keys.hmacKey, sizeof(keys.hmacKey), buf.data(), buf.size(), mac8, 8)) {
    memset(mac8, 0, 8);
  }

  ciphertext = std::move(buf);
}

static bool pipelineDecrypt(const DerivedKeys& keys,
                            const uint8_t* cipher, size_t cipherLen,
                            const GridSpec& grid,
                            const uint8_t mac8[8],
                            std::vector<uint8_t>& recovered) {
  uint8_t mac_check[8];
  if (!hmac_sha256_trunc(keys.hmacKey, sizeof(keys.hmacKey), cipher, cipherLen, mac_check, 8)) {
    return false;
  }
  if (memcmp(mac_check, mac8, 8) != 0) {
    Serial.println("MAC verification failed!");
    return false;
  }

  std::vector<uint8_t> buf(cipher, cipher + cipherLen);
  applyTransposition(buf.data(), grid, keys.transpositionKey, PermuteMode::Inverse);

  {
    Tinkerbell tk(keys.tinkerbellKey);
    tk.xorBitwise(buf.data(), buf.size());
  }
  {
    LFSR16 lfsr(keys.lfsrSeed, 0x0029);
    std::vector<uint8_t> ks(buf.size());
    lfsr.generate(ks.data(), ks.size());
    for (size_t i = 0; i < buf.size(); ++i) buf[i] ^= ks[i];
  }

  recovered = std::move(buf);
  return true;
}

// Globals for periodic runs
static DerivedKeys gKeys;
static uint8_t gMasterKey[32];
static bool gReady = false;
static int gCycles = 0;
static uint32_t gLastRunMs = 0;

static void printEntropySummary(const EntropyReport& er) {
  Serial.printf("Entropy time_us: %llu\n", (unsigned long long)er.time_us);
  Serial.print("Entropy MAC: ");
  for (int i = 0; i < 6; ++i) { Serial.printf("%02X", er.mac[i]); if (i<5) Serial.print(":"); }
  Serial.println();
  Serial.print("Entropy analog[0..3]: ");
  for (int i = 0; i < 4; ++i) Serial.printf("%u ", er.analog_samples[i]);
  Serial.println();
  Serial.print("Entropy jitter[0..3]: ");
  for (int i = 0; i < 4; ++i) Serial.printf("%u ", er.jitter[i]);
  Serial.println();
}

static void runOnceWithMessage(const char* label, const uint8_t* plain, size_t plen, bool verbose) {
  // Per-message salt (example length 2 bytes)
  uint8_t salt[2];
  uint32_t r = esp_random();
  salt[0] = (uint8_t)(r & 0xFF);
  salt[1] = (uint8_t)((r >> 8) & 0xFF);

  // Choose salt position (example: after end of plaintext)
  SaltMeta meta{ (uint16_t)plen, (uint8_t)sizeof(salt) };

  Serial.printf("\n--- %s ---\n", label);
  asciiPrint("Plaintext", plain, plen);
  hexPrint("Plaintext (hex)", plain, plen);
  Serial.printf("Salt (hex): %02X%02X, position: %u\n", salt[0], salt[1], meta.pos);

  // Insert salt and show
  std::vector<uint8_t> salted = insertSalt(plain, plen, salt, sizeof(salt), meta);
  asciiPrint("Plain + Salt", salted.data(), salted.size());
  hexPrint("Plain + Salt (hex)", salted.data(), salted.size());

  GridSpec grid = selectGrid(salted.size());
  std::vector<uint8_t> ct;
  uint8_t mac8[8];
  pipelineEncrypt(gKeys, salted.data(), salted.size(), grid, ct, mac8, verbose);

  hexPrint("Ciphertext", ct.data(), ct.size());
  hexPrint("HMAC-8", mac8, 8);

  // Decrypt to verify and remove salt
  std::vector<uint8_t> rec;
  if (pipelineDecrypt(gKeys, ct.data(), ct.size(), grid, mac8, rec)) {
    hexPrint("Recovered (with salt)", rec.data(), rec.size());
    std::vector<uint8_t> orig = removeSalt(rec.data(), rec.size(), meta);
    asciiPrint("Recovered (salt removed)", orig.data(), orig.size());
    hexPrint("Recovered (salt removed hex)", orig.data(), orig.size());
  } else {
    Serial.println("Decrypt failed");
  }
}

void setup() {
  Serial.begin(115200);
  delay(1500);

  Serial.println("\n=== XenoCipher Component Pipeline (PlatformIO) ===");

  // 1) Gather entropy and build 32-byte master key
  EntropyReport er{};
  if (!gatherMasterKey(gMasterKey, &er)) {
    Serial.println("Entropy collection failed!");
    while (true) delay(1000);
  }
  hexPrint("Master key (32)", gMasterKey, 32);
  printEntropySummary(er);

  // 2) Derive subkeys (PBKDF2-HMAC-SHA256 from master key only; no per-message salt mixed in)
  if (!deriveKeys(gMasterKey, sizeof(gMasterKey), gKeys)) {
    Serial.println("KDF failed!");
    while (true) delay(1000);
  }
  Serial.printf("LFSR seed: 0x%04X\n", gKeys.lfsrSeed);
  hexPrint("Tinkerbell key", gKeys.tinkerbellKey, 8);
  hexPrint("Transposition key", gKeys.transpositionKey, 8);

  // 3) Example 1: "Xenocipher" (like your blueprint); verbose = true to show all layers
  const char* msg1 = "Xenocipher";
  runOnceWithMessage("Example#1 (Xenocipher)", (const uint8_t*)msg1, strlen(msg1), true);

  // 4) Example 2: three lines health string; verbose = true
  const char* msg2 = "IR-112781\r\nBPM-7509\r\nAVG BPM-81";
  runOnceWithMessage("Example#2 (3-line health block)", (const uint8_t*)msg2, strlen(msg2), true);

  Serial.println("\nEntering periodic mode (30 cycles) with dummy sensor data...");
  gReady = true;
  gLastRunMs = millis();
}

static void buildDummySensorLine(char* out, size_t outCap, uint16_t hr, uint8_t spo2) {
  // Example: "HR-75 SPO2-98"
  snprintf(out, outCap, "HR-%u SPO2-%u", (unsigned)hr, (unsigned)spo2);
}

void loop() {
  if (!gReady) {
    delay(100);
    return;
  }

  uint32_t now = millis();
  if (now - gLastRunMs >= 3000 && gCycles < 30) {
    gLastRunMs = now;
    // Simulate readings
    uint16_t hr = 60 + (esp_random() % 45);      // 60..104
    uint8_t spo2 = 95 + (esp_random() % 5);      // 95..99

    char line[48];
    buildDummySensorLine(line, sizeof(line), hr, spo2);

    // Verbose only for first few cycles; then concise
    bool verbose = (gCycles < 2);

    runOnceWithMessage("Periodic sensor payload", (const uint8_t*)line, strlen(line), verbose);

    gCycles++;
    if (gCycles == 30) {
      Serial.println("\nReached 30 cycles. Pausing periodic encryption.");
    }
  }
}
