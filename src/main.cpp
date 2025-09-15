#include <Arduino.h>
#include <vector>
#include <mbedtls/sha256.h>
#include <nvs_flash.h>
#include <nvs.h>

#include "../lib/CryptoKDF/include/crypto_kdf.h"
#include "../lib/LFSR/include/lfsr.h"
#include "../lib/Tinkerbell/include/tinkerbell.h"
#include "../lib/Transposition/include/transposition.h"
#include "../lib/HMAC/include/hmac.h"
#include "../lib/Entropy/include/entropy.h"
#include "../lib/NTRU/include/ntru.h"

#ifndef HMAC_TAG_LEN
#define HMAC_TAG_LEN 16
#endif

#define VERSION_BASE 0x01
#define VERSION_NONCE_EXT 0x81

static void hexPrint(const char* label, const uint8_t* data, size_t n) {
  Serial.printf("%s (%u): ", label, (unsigned)n);
  for (size_t i = 0; i < n; ++i) {
    Serial.printf("%02X", data[i]);
    if ((i + 1) % 16 == 0) Serial.print(" ");
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
  uint16_t pos;
  uint8_t len;
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
  if (len <= 12) return GridSpec{4, 3};
  if (len <= 32) return GridSpec{4, 8};
  if (len <= 64) return GridSpec{8, 8};
  size_t cols = 16;
  size_t rows = (len + cols - 1) / cols;
  if (rows < 4) rows = 4;
  return GridSpec{rows, cols};
}

static void store_public_key(const std::vector<uint8_t>& pub_bytes) {
  nvs_handle_t handle;
  if (nvs_open("storage", NVS_READWRITE, &handle) != ESP_OK) {
    Serial.println("NVS open failed");
    return;
  }
  esp_err_t err = nvs_set_blob(handle, "ntru_pub", pub_bytes.data(), pub_bytes.size());
  if (err != ESP_OK) {
    Serial.printf("NVS set_blob failed: %d\n", (int)err);
    nvs_close(handle);
    return;
  }
  err = nvs_commit(handle);
  if (err != ESP_OK) {
    Serial.printf("NVS commit failed: %d\n", (int)err);
  } else {
    Serial.printf("Saved public key (%u bytes) to NVS.\n", (unsigned)pub_bytes.size());
  }
  nvs_close(handle);
}

static bool parse_hex(const String& hex, std::vector<uint8_t>& out) {
  out.clear();
  String s;
  s.reserve(hex.length());
  for (size_t i = 0; i < (size_t)hex.length(); ++i) {
    char c = hex[i];
    if (c == ' ' || c == '\t' || c == '\r' || c == '\n') continue;
    s += c;
  }
  if ((s.length() & 1) != 0) return false;
  out.reserve(s.length() / 2);
  for (size_t i = 0; i < (size_t)s.length(); i += 2) {
    char hi = s[i];
    char lo = s[i+1];
    auto hexval = [](char ch) -> int {
      if (ch >= '0' && ch <= '9') return ch - '0';
      if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
      if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
      return -1;
    };
    int h = hexval(hi);
    int l = hexval(lo);
    if (h < 0 || l < 0) return false;
    out.push_back((uint8_t)((h << 4) | l));
  }
  return true;
}

static void send_master_key(const uint8_t* master_key, size_t key_len) {
  NTRU ntru;
  Poly m, e;
  NTRU::bytes_to_poly(std::vector<uint8_t>(master_key, master_key + key_len), m, key_len);
  
  std::vector<uint8_t> pub_bytes(NTRU_N * 2);
  nvs_handle_t handle;
  if (nvs_open("storage", NVS_READONLY, &handle) != ESP_OK) {
    Serial.println("NVS open failed for public key");
    return;
  }
  size_t len = pub_bytes.size();
  esp_err_t err = nvs_get_blob(handle, "ntru_pub", pub_bytes.data(), &len);
  nvs_close(handle);
  if (err != ESP_OK) {
    Serial.printf("NVS get_blob failed: %d\n", (int)err);
    return;
  }
  
  Poly h;
  for (int i = 0; i < NTRU_N; ++i) {
    h.coeffs[i] = (pub_bytes[i * 2] << 8) | pub_bytes[i * 2 + 1];
  }
  
  ntru.encrypt(m, h, e);
  std::vector<uint8_t> e_bytes(NTRU_N * 2);
  for (int i = 0; i < NTRU_N; ++i) {
    e_bytes[i * 2] = e.coeffs[i] >> 8;
    e_bytes[i * 2 + 1] = e.coeffs[i] & 0xFF;
  }
  
  Serial.print("ENCKEY:");
  for (uint8_t b : e_bytes) {
    Serial.printf("%02X", b);
  }
  Serial.println();
}

static void generateHealthData(char* buffer, size_t buffer_size, uint32_t cycle) {
  // Simulate health data (heart rate: 60-100, SpO2: 95-100, steps: 0-10000)
  uint8_t heart_rate = 60 + (esp_random() % 41); // 60-100
  uint8_t spo2 = 95 + (esp_random() % 6);       // 95-100
  uint16_t steps = esp_random() % 10001;        // 0-10000
  snprintf(buffer, buffer_size, "HR-%u SPO2-%u STEPS-%u", heart_rate, spo2, steps);
}

static bool upload_encrypted_data(const std::vector<uint8_t>& packet) {
  Serial.print("ENC_DATA:");
  for (uint8_t b : packet) {
    Serial.printf("%02X", b);
  }
  Serial.println();
  unsigned long start = millis();
  while (millis() - start < 5000) { // 5-second timeout
    if (Serial.available()) {
      String line = Serial.readStringUntil('\n');
      line.trim();
      if (line == "ENC_OK:Stored") {
        Serial.println("Encrypted data stored successfully");
        return true;
      } else if (line.startsWith("ENC_ERR:")) {
        Serial.println("Upload error: " + line.substring(8));
        return false;
      }
    }
    delay(10);
  }
  Serial.println("Upload timeout");
  return false;
}

static DerivedKeys gBaseKeys;
static uint8_t gMasterKey[32];
static bool gReady = false;
static int gCycles = 0;
static uint32_t gLastRunMs = 0;

static void writeHeader(uint8_t* hdr8,
                        uint8_t version,
                        uint8_t salt_len,
                        uint16_t salt_pos,
                        uint16_t payload_len,
                        uint8_t rows,
                        uint8_t cols) {
  hdr8[0] = version;
  hdr8[1] = salt_len;
  hdr8[2] = (uint8_t)(salt_pos & 0xFF);
  hdr8[3] = (uint8_t)((salt_pos >> 8) & 0xFF);
  hdr8[4] = (uint8_t)(payload_len & 0xFF);
  hdr8[5] = (uint8_t)((payload_len >> 8) & 0xFF);
  hdr8[6] = rows;
  hdr8[7] = cols;
}

static void pipelineEncryptPacket(const DerivedKeys& baseKeys,
                                  uint32_t nonce, bool includeNonceExt,
                                  const uint8_t* salted, size_t saltedLen,
                                  const GridSpec& grid,
                                  uint8_t salt_len, uint16_t salt_pos, uint16_t payload_len,
                                  std::vector<uint8_t>& packet,
                                  bool verbose) {
  MessageKeys mk;
  if (!deriveMessageKeys(baseKeys, nonce, mk)) {
    Serial.println("deriveMessageKeys failed!");
    packet.clear(); return;
  }

  std::vector<uint8_t> buf = padToGrid(salted, saltedLen, grid);
  if (verbose) hexPrint("Plain (padded)", buf.data(), buf.size());

  {
    ChaoticLFSR32 lfsr((uint32_t)mk.lfsrSeed, mk.tinkerbellKey, 0x0029u);
    lfsr.xorBuffer(buf.data(), buf.size());
    if (verbose) hexPrint("After ChaoticLFSR", buf.data(), buf.size());
  }

  {
    Tinkerbell tk(mk.tinkerbellKey);
    tk.xorBitwise(buf.data(), buf.size());
    if (verbose) hexPrint("After Tinkerbell", buf.data(), buf.size());
  }

  {
    applyTransposition(buf.data(), grid, mk.transpositionKey, PermuteMode::Forward);
    if (verbose) hexPrint("After Transposition", buf.data(), buf.size());
  }

  const size_t headerLen = 8;
  const size_t nonceLen = includeNonceExt ? 4 : 0;
  const size_t tagLen = HMAC_TAG_LEN;
  packet.resize(headerLen + nonceLen + buf.size() + tagLen);

  uint8_t* p = packet.data();
  uint8_t version = includeNonceExt ? VERSION_NONCE_EXT : VERSION_BASE;
  writeHeader(p, version, salt_len, salt_pos, payload_len,
              (uint8_t)grid.rows, (uint8_t)grid.cols);

  if (includeNonceExt) {
    p[8] = (uint8_t)((nonce >> 24) & 0xFF);
    p[9] = (uint8_t)((nonce >> 16) & 0xFF);
    p[10] = (uint8_t)((nonce >> 8) & 0xFF);
    p[11] = (uint8_t)(nonce & 0xFF);
  }

  memcpy(p + headerLen + nonceLen, buf.data(), buf.size());

  if (!hmac_sha256_trunc(baseKeys.hmacKey, sizeof(baseKeys.hmacKey),
                         packet.data(), headerLen + nonceLen + buf.size(),
                         p + headerLen + nonceLen + buf.size(), tagLen)) {
    memset(p + headerLen + nonceLen + buf.size(), 0, tagLen);
  }
}

static bool pipelineDecryptPacket(const DerivedKeys& baseKeys,
                                  const uint8_t* packet, size_t packetLen,
                                  std::vector<uint8_t>& recovered,
                                  SaltMeta& saltMetaOut,
                                  GridSpec& gridOut) {
  if (packetLen < 8 + HMAC_TAG_LEN) return false;
  const uint8_t* header = packet;
  uint8_t version = header[0];
  bool hasNonce = (version & 0x80) != 0;
  size_t nonceLen = hasNonce ? 4 : 0;
  if (packetLen < 8 + nonceLen + HMAC_TAG_LEN) return false;

  uint8_t salt_len = header[1];
  uint16_t salt_pos = (uint16_t)(header[2] | (header[3] << 8));
  uint16_t payload_len = (uint16_t)(header[4] | (header[5] << 8));
  uint8_t rows = header[6];
  uint8_t cols = header[7];

  gridOut = GridSpec{rows, cols};
  saltMetaOut = SaltMeta{salt_pos, salt_len};

  const uint8_t* noncePtr = hasNonce ? packet + headerLen : nullptr;
  uint32_t nonce = 0;
  if (hasNonce) {
    nonce = ((uint32_t)noncePtr[0] << 24) |
            ((uint32_t)noncePtr[1] << 16) |
            ((uint32_t)noncePtr[2] << 8) |
            ((uint32_t)noncePtr[3]);
  }
  const uint8_t* ct = packet + headerLen + nonceLen;
  size_t ctLen = packetLen - headerLen - nonceLen - HMAC_TAG_LEN;
  const uint8_t* tag = ct + ctLen;

  uint8_t tagCheck[32];
  if (!hmac_sha256_trunc(baseKeys.hmacKey, sizeof(baseKeys.hmacKey),
                         packet, headerLen + nonceLen + ctLen,
                         tagCheck, HMAC_TAG_LEN)) return false;

  bool macValid = true;
  for (size_t i = 0; i < HMAC_TAG_LEN; ++i) {
    if (tag[i] != tagCheck[i]) macValid = false;
  }
  memset(tagCheck, 0, sizeof(tagCheck));

  if (!macValid) {
    Serial.println("MAC verification failed!");
    return false;
  }

  Serial.println("✓ HMAC validation successful!");

  MessageKeys mk;
  if (!deriveMessageKeys(baseKeys, nonce, mk)) return false;

  std::vector<uint8_t> buf(ct, ct + ctLen);

  applyTransposition(buf.data(), gridOut, mk.transpositionKey, PermuteMode::Inverse);

  {
    Tinkerbell tk(mk.tinkerbellKey);
    tk.xorBitwise(buf.data(), buf.size());
  }

  {
    ChaoticLFSR32 lfsr((uint32_t)mk.lfsrSeed, mk.tinkerbellKey, 0x0029u);
    lfsr.xorBuffer(buf.data(), buf.size());
  }

  recovered = std::move(buf);
  (void)payload_len;
  return true;
}

static void printEntropySummary(const EntropyReport& er) {
  Serial.printf("Entropy time_us: %llu\n", (unsigned long long)er.time_us);
  Serial.print("Entropy MAC: ");
  for (int i = 0; i < 6; ++i) {
    Serial.printf("%02X", er.mac[i]);
    if (i < 5) Serial.print(":");
  }
  Serial.println();
  Serial.print("Entropy analog[0..3]: ");
  for (int i = 0; i < 4; ++i) Serial.printf("%u ", er.analog_samples[i]);
  Serial.println();
  Serial.print("Entropy jitter[0..3]: ");
  for (int i = 0; i < 4; ++i) Serial.printf("%u ", 0u);
  Serial.println();
}

static void runOnceWithMessage(const char* label, const uint8_t* plain, size_t plen, uint32_t nonce, bool verbose) {
  Serial.printf("\n--- %s ---\n", label);
  asciiPrint("Plaintext", plain, plen);
  hexPrint("Plaintext (hex)", plain, plen);
  Serial.printf("Nonce: %08X\n", (unsigned)nonce);

  SaltMeta meta;
  GridSpec grid = selectGrid(plen + 2);

  uint8_t salt[2];
  uint32_t r = esp_random();
  salt[0] = (uint8_t)(r & 0xFF);
  salt[1] = (uint8_t)((r >> 8) & 0xFF);
  meta = {(uint16_t)plen, (uint8_t)sizeof(salt)};

  std::vector<uint8_t> salted = insertSalt(plain, plen, salt, sizeof

System: salt), meta);

  asciiPrint("Plain + Salt", salted.data(), salted.size());
  hexPrint("Plain + Salt (hex)", salted.data(), salted.size());

  std::vector<uint8_t> packet;
  pipelineEncryptPacket(gBaseKeys, nonce, true, salted.data(), salted.size(), grid,
                        meta.len, meta.pos, (uint16_t)plen, packet, verbose);

  hexPrint("Header(8)", packet.data(), 8);
  hexPrint("Nonce(4)", packet.data() + 8, 4);

  size_t headerLen = 8;
  size_t nonceLen = 4;
  size_t ctLen = packet.size() - headerLen - nonceLen - HMAC_TAG_LEN;
  const uint8_t* ct = packet.data() + headerLen + nonceLen;
  const uint8_t* tag = ct + ctLen;

  hexPrint("Ciphertext", ct, ctLen);
  hexPrint("HMAC", tag, HMAC_TAG_LEN);

  upload_encrypted_data(packet);

  std::vector<uint8_t> rec;
  SaltMeta parsed{};
  GridSpec parsedGrid{};
  if (pipelineDecryptPacket(gBaseKeys, packet.data(), packet.size(), rec, parsed, parsedGrid)) {
    hexPrint("Recovered (with salt, padded)", rec.data(), rec.size());
    std::vector<uint8_t> orig = removeSalt(rec.data(), rec.size(), parsed);
    asciiPrint("Recovered (salt removed)", orig.data(), orig.size());
    hexPrint("Recovered (salt removed hex)", orig.data(), orig.size());
  } else {
    Serial.println("Decrypt failed");
  }
}

void setup() {
  Serial.begin(115200);
  delay(1500);

  Serial.println("\n=== XenoCipher Authenticated Pipeline ===");
  Serial.printf("PBKDF2 iterations: %u | HMAC tag len: %u bytes\n", (unsigned)KDF_ITERATIONS, (unsigned)HMAC_TAG_LEN);

  esp_err_t nvs_err = nvs_flash_init();
  if (nvs_err == ESP_ERR_NVS_NO_FREE_PAGES || nvs_err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    nvs_flash_erase();
    nvs_err = nvs_flash_init();
  }
  if (nvs_err != ESP_OK) {
    Serial.printf("NVS init failed: %d\n", (int)nvs_err);
  }

  EntropyReport er{};
  if (!gatherMasterKey(gMasterKey, &er)) {
    Serial.println("Entropy collection failed!");
    while (true) delay(1000);
  }
  hexPrint("Master key (32)", gMasterKey, 32);
  printEntropySummary(er);

  send_master_key(gMasterKey, sizeof(gMasterKey));

  if (!deriveKeys(gMasterKey, sizeof(gMasterKey), gBaseKeys)) {
    Serial.println("KDF failed!");
    while (true) delay(1000);
  }
  Serial.printf("Base LFSR seed: 0x%04X\n", gBaseKeys.lfsrSeed);
  hexPrint("Base Tinkerbell key", gBaseKeys.tinkerbellKey, 8);
  hexPrint("Base Transposition key", gBaseKeys.transpositionKey, 8);

  memset(gMasterKey, 0, sizeof(gMasterKey));

  uint32_t nonce1 = esp_random();
  const char* msg1 = "Xenocipher";
  runOnceWithMessage("Example#1", (const uint8_t*)msg1, strlen(msg1), nonce1, true);

  uint32_t nonce2 = esp_random();
  const char* msg2 = "IR-112781\r\nBPM-7509\r\nAVG BPM-81";
  runOnceWithMessage("Example#2", (const uint8_t*)msg2, strlen(msg2), nonce2, true);

  Serial.println("\nEntering periodic mode (30 cycles)...");
  gReady = true;
  gLastRunMs = millis();
}

void loop() {
  if (!gReady) {
    delay(100);
    return;
  }

  if (Serial.available()) {
    String line = Serial.readStringUntil('\n');
    line.trim();
    if (line.startsWith("PUBHEX:")) {
      String hex = line.substring(7);
      std::vector<uint8_t> bytes;
      if (parse_hex(hex, bytes)) {
        store_public_key(bytes);
        Serial.println("OK:Public key stored");
      } else {
        Serial.println("ERR:Invalid hex");
      }
    }
  }

  uint32_t now = millis();
  if (now - gLastRunMs >= 3000 && gCycles < 30) {
    gLastRunMs = now;
    char data[48];
    generateHealthData(data, sizeof(data), gCycles + 1);
    uint32_t nonce = esp_random();
    bool verbose = (gCycles < 2);
    runOnceWithMessage("Periodic sensor payload", (const uint8_t*)data, strlen(data), nonce, verbose);
    gCycles++;
    if (gCycles == 30) {
      Serial.println("\nReached 30 cycles. Pausing periodic encryption.");
    }
  }
}