#include <Arduino.h>
#include <WiFi.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include <nvs_flash.h>
#include <esp_random.h>
#include <common.h>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <regex>
#include <cstring>

#include "crypto_kdf.h"
#include "lfsr.h"
#include "tinkerbell.h"
#include "transposition.h"
#include "hmac.h"
#include "entropy.h"

#include "../lib/NTRU/include/ntru.h"

#ifndef HMAC_TAG_LEN
#define HMAC_TAG_LEN 16
#endif

#define VERSION_BASE 0x01
#define VERSION_NONCE_EXT 0x81

// Configuration
#define SERVER_URL "http://10.207.139.115:8081"  // Your server IP and port
#define WIFI_SSID "motorola edge 40_6753"  //Galaxy M322E19
#define WIFI_PASSWORD "subviv123"
#define HEALTH_DATA_INTERVAL_MS 10000
#define CONNECTION_TIMEOUT_MS 10000
#define MAX_RETRIES 3

// NVS Storage Keys
#define NVS_NAMESPACE "xenocipher"
#define NVS_PUBKEY_KEY "ntru_pub"
#define NVS_MASTER_KEY_KEY "master_key"

// State machine
enum CommState {
  STATE_INIT_NVS,
  STATE_CONNECT_WIFI,
  STATE_CHECK_PUBLIC_KEY,
  STATE_GET_PUBLIC_KEY,
  STATE_GENERATE_MASTER_KEY,
  STATE_ENCRYPT_MASTER_KEY,
  STATE_SEND_MASTER_KEY,
  STATE_DERIVE_SYMMETRIC,
  STATE_SEND_HEALTH_DATA,
  STATE_ERROR
};

// Global state
static CommState currentState = STATE_INIT_NVS;
static bool masterKeyReady = false;
static bool publicKeyLoaded = false;
static uint32_t lastHealthSend = 0;
static int healthSendCount = 0;
static int retryCount = 0;
static bool wifiAttemptInProgress = false;
static unsigned long wifiAttemptStartMs = 0;

// Global keys and buffers
static DerivedKeys gBaseKeys;
static uint8_t gMasterKey[32];
static std::vector<uint8_t> gPublicKey;

// Salt metadata used in packet formatting
struct SaltMeta {
  uint16_t pos;
  uint8_t len;
};

// Forward declarations for helpers used before definitions
static bool derive_symmetric_keys();
static std::vector<uint8_t> insertSalt(const uint8_t* plain, size_t plen,
                                       const uint8_t* salt, uint8_t slen,
                                       const SaltMeta& meta);
static std::vector<uint8_t> removeSalt(const uint8_t* salted, size_t slenTotal,
                                       const SaltMeta& meta);
static std::vector<uint8_t> padToGrid(const uint8_t* in, size_t len, const GridSpec& g);
static GridSpec selectGrid(size_t len);
static void writeHeader(uint8_t* hdr8,
                        uint8_t version,
                        uint8_t salt_len,
                        uint16_t salt_pos,
                        uint16_t payload_len,
                        uint8_t rows,
                        uint8_t cols);
static void pipelineEncryptPacket(const DerivedKeys& baseKeys,
                                  uint32_t nonce, bool includeNonceExt,
                                  const uint8_t* salted, size_t saltedLen,
                                  const GridSpec& grid,
                                  uint8_t salt_len, uint16_t salt_pos, uint16_t payload_len,
                                  std::vector<uint8_t>& packet,
                                  bool verbose);

// Utility functions
static void hexPrint(const char* label, const uint8_t* data, size_t n) {
  Serial.printf("%s (%u): ", label, (unsigned)n);
  for (size_t i = 0; i < n && i < 32; ++i) {  // Limit to 32 bytes for readability
    Serial.printf("%02X", data[i]);
    if ((i + 1) % 16 == 0) Serial.print(" ");
  }
  if (n > 32) Serial.print("...");
  Serial.println();
}

static void asciiPrint(const char* label, const uint8_t* data, size_t n) {
  Serial.printf("%s (%u): ", label, (unsigned)n);
  for (size_t i = 0; i < n && i < 32; ++i) {  // Limit to 32 bytes
    char c = (char)data[i];
    Serial.print(isprint((unsigned char)c) ? c : '.');
  }
  Serial.println();
}

static void printStatus(const char* stateName) {
  Serial.printf("[%.1f] STATE: %s | WiFi: %s | MasterKey: %s | HealthSent: %d\n",
    millis() / 1000.0, stateName,
    WiFi.status() == WL_CONNECTED ? "OK" : "DOWN",
    masterKeyReady ? "READY" : "PENDING",
    healthSendCount);
}

// WiFi event logger
static void onWiFiEvent(WiFiEvent_t event, WiFiEventInfo_t info) {
  switch (event) {
    case SYSTEM_EVENT_STA_START: Serial.println("[WiFi] STA Start"); break;
    case SYSTEM_EVENT_STA_CONNECTED: Serial.println("[WiFi] Connected to AP"); break;
    case SYSTEM_EVENT_STA_GOT_IP:
      Serial.printf("[WiFi] Got IP: %s\n", WiFi.localIP().toString().c_str());
      break;
    case SYSTEM_EVENT_STA_DISCONNECTED:
      Serial.printf("[WiFi] Disconnected, reason=%u\n", info.wifi_sta_disconnected.reason);
      wifiAttemptInProgress = false;
      break;
    default: break;
  }
}

// NVS Storage functions
static bool store_public_key_nvs(const std::vector<uint8_t>& pub_bytes) {
  nvs_handle_t handle;
  esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &handle);
  if (err != ESP_OK) {
    Serial.printf("NVS open failed: %s\n", esp_err_to_name(err));
    return false;
  }
  err = nvs_set_blob(handle, NVS_PUBKEY_KEY, pub_bytes.data(), pub_bytes.size());
  if (err != ESP_OK) {
    Serial.printf("NVS set_blob failed: %s\n", esp_err_to_name(err));
    nvs_close(handle);
    return false;
  }
  err = nvs_commit(handle);
  nvs_close(handle);
  if (err == ESP_OK) {
    Serial.printf("✓ Stored public key (%u bytes) in NVS\n", (unsigned)pub_bytes.size());
    return true;
  }
  Serial.printf("NVS commit failed: %s\n", esp_err_to_name(err));
  return false;
}

static bool load_public_key_nvs(std::vector<uint8_t>& pub_bytes) {
  nvs_handle_t handle;
  esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READONLY, &handle);
  if (err != ESP_OK) return false;
  size_t required_size = 0;
  err = nvs_get_blob(handle, NVS_PUBKEY_KEY, nullptr, &required_size);
  if (err != ESP_OK && err != ESP_ERR_NVS_NOT_FOUND) {
    nvs_close(handle);
    return false;
  }
  if (required_size == 0) {
    nvs_close(handle);
    return false;
  }
  pub_bytes.resize(required_size);
  err = nvs_get_blob(handle, NVS_PUBKEY_KEY, pub_bytes.data(), &required_size);
  nvs_close(handle);
  if (err == ESP_OK) {
    Serial.printf("✓ Loaded public key (%u bytes) from NVS\n", (unsigned)required_size);
    return true;
  }
  return false;
}

static bool store_master_key_nvs(const uint8_t* key, size_t key_len) {
  nvs_handle_t handle;
  esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &handle);
  if (err != ESP_OK) return false;
  err = nvs_set_blob(handle, NVS_MASTER_KEY_KEY, key, key_len);
  if (err == ESP_OK) {
    err = nvs_commit(handle);
  }
  nvs_close(handle);
  return (err == ESP_OK);
}

// Hex parsing
static bool parse_hex_string(const String& hex, std::vector<uint8_t>& out) {
  out.clear();
  String cleanHex = hex;
  cleanHex.toUpperCase();
  cleanHex.replace(" ", "");
  cleanHex.replace(":", "");
  if (cleanHex.length() % 2 != 0) return false;
  out.reserve(cleanHex.length() / 2);
  for (size_t i = 0; i < cleanHex.length(); i += 2) {
    String byteStr = cleanHex.substring(i, i + 2);
    uint8_t byte = (uint8_t)strtol(byteStr.c_str(), nullptr, 16);
    out.push_back(byte);
  }
  return true;
}

// HTTP Functions
static bool http_get_public_key() {
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("WiFi not connected");
    return false;
  }

  HTTPClient http;
  String url = String(SERVER_URL) + "/public-key";
  Serial.printf("GET %s\n", url.c_str());
  
  http.begin(url);
  http.setTimeout(CONNECTION_TIMEOUT_MS);
  
  int httpCode = http.GET();
  if (httpCode == HTTP_CODE_OK) {
    String response = http.getString();
    Serial.printf("Response (%u chars): %s\n", response.length(), response.substring(0, 100).c_str());

    // Minimal parse to reduce stack usage
    int keyPos = response.indexOf("\"publicKey\"");
    if (keyPos >= 0) {
      int pubhexPos = response.indexOf("PUBHEX:", keyPos);
      if (pubhexPos >= 0) {
        int start = pubhexPos + 7;
        int end = response.indexOf('"', start);
        if (end < 0) end = response.length();
        String hexStr = response.substring(start, end);
        hexStr.trim();

        std::vector<uint8_t> pubBytes;
        if (parse_hex_string(hexStr, pubBytes)) {
          if (store_public_key_nvs(pubBytes)) {
            gPublicKey = pubBytes;
            publicKeyLoaded = true;
            http.end();
            return true;
          }
        } else {
          Serial.println("Failed to parse PUBHEX hex");
        }
      } else {
        Serial.println("PUBHEX: not found in response");
      }
    } else {
      Serial.println("'publicKey' not found in response");
    }
  } else {
    Serial.printf("HTTP GET failed - Code: %d\n", httpCode);
  }
  
  http.end();
  return false;
}

static String to_hex_string(const std::vector<uint8_t>& data) {
  String dataHex;
  dataHex.reserve(data.size() * 2);
  for (uint8_t b : data) {
    char hexChar[3];
    sprintf(hexChar, "%02X", b);
    dataHex += hexChar;
  }
  return dataHex;
}

static bool http_post_json(const String& endpoint, const String& key, const String& valueWithPrefix) {
  if (WiFi.status() != WL_CONNECTED) return false;

  HTTPClient http;
  String url = String(SERVER_URL) + endpoint;
  Serial.printf("POST %s\n", url.c_str());
  
  http.begin(url);
  http.addHeader("Content-Type", "application/json");
  http.setTimeout(CONNECTION_TIMEOUT_MS);
  
  // Create JSON payload
  String jsonPayload = String("{") + "\"" + key + "\":\"" + valueWithPrefix + "\"}";
  
  int httpCode = http.POST(jsonPayload);
  String response = http.getString();
  
  if (httpCode == HTTP_CODE_OK) {
    Serial.printf("HTTP %d - Response: %s\n", httpCode, response.c_str());
    if (response.indexOf("OK:") >= 0 || response.indexOf("ENC_OK") >= 0) {
      Serial.println("✓ Server accepted data");
      http.end();
      return true;
    } else {
      Serial.println("✗ Server rejected data");
    }
  } else {
    Serial.printf("HTTP POST failed - Code: %d\n", httpCode);
  }
  
  http.end();
  return false;
}

static bool http_post_enc_key(const std::vector<uint8_t>& encKey) {
  String hex = to_hex_string(encKey);
  return http_post_json("/master-key", "encKey", String("ENCKEY:") + hex);
}

static bool http_post_enc_data(const std::vector<uint8_t>& packet) {
  String hex = to_hex_string(packet);
  return http_post_json("/health-data", "encData", String("ENC_DATA:") + hex);
}

// NTRU Master Key Encryption
static bool generate_and_encrypt_master_key() {
  // Always generate a fresh master key to ensure consistency
  Serial.println("Generating fresh master key from entropy...");
  
  EntropyReport er{};
  if (!gatherMasterKey(gMasterKey, &er)) {
    Serial.println("✗ Entropy collection failed");
    return false;
  }
  
  hexPrint("Generated master key", gMasterKey, 32);
  printEntropySummary(&er);
  
  Serial.println("Using original unreduced master key (no mod NTRU_P reduction)");
  
  // Store original master key in NVS (no reduction)
  if (!store_master_key_nvs(gMasterKey, 32)) {
    Serial.println("✗ Failed to store master key in NVS");
    memset(gMasterKey, 0, 32);
    return false;
  }
  
  // Encrypt with NTRU using the SAME original key that we stored
  NTRU ntru;
  Poly m, e, h;
  
  NTRU::bytes_to_poly(std::vector<uint8_t>(gMasterKey, gMasterKey + 32), m, 32);
  
  if (gPublicKey.empty() || gPublicKey.size() != NTRU_N * 2) {
    Serial.println("✗ Invalid public key");
    memset(gMasterKey, 0, 32);
    return false;
  }
  
  // Convert public key bytes to polynomial
  for (int i = 0; i < NTRU_N; ++i) {
    h.coeffs[i] = (gPublicKey[i * 2] << 8) | gPublicKey[i * 2 + 1];
  }
  
  ntru.encrypt(m, h, e);
  
  std::vector<uint8_t> encryptedKey(NTRU_N * 2);
  for (int i = 0; i < NTRU_N; ++i) {
    encryptedKey[i * 2] = e.coeffs[i] >> 8;
    encryptedKey[i * 2 + 1] = e.coeffs[i] & 0xFF;
  }
  
  hexPrint("NTRU encrypted master key", encryptedKey.data(), encryptedKey.size());
  
  Serial.printf("Encrypting the same original key that was stored in NVS (no reduction)\n");
  
  // Send to server
  bool success = http_post_enc_key(encryptedKey);
  
  // Clear sensitive data
  memset(gMasterKey, 0, 32);
  
  return success;
}

// Health Data Generation and Encryption
static void generate_realistic_health_data(char* buffer, size_t buffer_size, uint32_t timestamp) {
  uint8_t heart_rate = 60 + ((timestamp / 60000) % 41);
  uint8_t spo2 = 95 + ((timestamp / 300000) % 6);
  uint16_t steps = (timestamp / 1000) * 5 + (esp_random() % 50);
  if (steps > 10000) steps = 0;
  if (esp_random() % 100 < 5) heart_rate += esp_random() % 5;
  snprintf(buffer, buffer_size, "HR-%u SPO2-%u STEPS-%u", heart_rate, spo2, steps);
}

static bool encrypt_and_send_health_data() {
  if (!masterKeyReady) {
    Serial.println("Master keys not ready");
    return false;
  }

  char healthBuffer[64];
  generate_realistic_health_data(healthBuffer, sizeof(healthBuffer), millis());
  Serial.printf("Generated health data: %s\n", healthBuffer);
  
  SaltMeta meta;
  // Use common salt from common.h
  meta.pos = (uint16_t)strlen(healthBuffer); // Add salt at end of data
  meta.len = 2; // Use first two bytes of common salt
  
  const uint8_t* plainData = (const uint8_t*)healthBuffer;
  
  size_t plainLen = strlen(healthBuffer);
  GridSpec grid = selectGrid(plainLen);
  uint32_t nonce = esp_random();
  std::vector<uint8_t> packet;
  
  // Encrypt with verbose output for first few packets
  bool verbose = healthSendCount < 3;
  pipelineEncryptPacket(gBaseKeys, nonce, true, plainData, plainLen, grid,
                        meta.len, meta.pos, plainLen, packet, verbose);
  
  if (packet.empty()) {
    Serial.println("Encryption failed - empty packet");
    return false;
  }
  
  hexPrint("Final encrypted packet", packet.data(), packet.size());
  
  // Send to server
  bool success = http_post_enc_data(packet);
  if (success) {
    healthSendCount++;
    Serial.printf("✓ Health data sent successfully (#%d)\n", healthSendCount);
  } else {
    Serial.println("✗ Failed to send health data to server");
  }
  
  return success;
}

// Salt and Grid functions (unchanged)
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
  if (len > 0 && in != nullptr) {
    memcpy(out.data(), in, len < need ? len : need);
  }
  return out;
}

static GridSpec selectGrid(size_t len) {
  if (len <= 12) return GridSpec{4, 3};
  if (len <= 32) return GridSpec{4, 8};
  if (len <= 64) return GridSpec{8, 8};
  size_t cols = 16;
  size_t rows = (len + cols - 1) / cols;
  if (rows < 4) rows = 4;
  return GridSpec{(uint8_t)rows, (uint8_t)cols};
}

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
                                  const uint8_t* data, size_t dataLen,
                                  const GridSpec& grid,
                                  uint8_t salt_len, uint16_t salt_pos, uint16_t payload_len,
                                  std::vector<uint8_t>& packet,
                                  bool verbose) {
  MessageKeys mk;
  if (!deriveMessageKeys(baseKeys, nonce, mk)) {
    Serial.println("deriveMessageKeys failed!");
    packet.clear();
    return;
  }

  // First add salt to the plain data
  std::vector<uint8_t> saltedData = insertSalt(data, dataLen, 
                                             (const uint8_t*)COMMON_SALT, salt_len, {salt_pos, salt_len});
  if (verbose) hexPrint("After Adding Salt", saltedData.data(), saltedData.size());

  // Pad the salted data to grid size
  std::vector<uint8_t> buf = padToGrid(saltedData.data(), saltedData.size(), grid);
  if (verbose) hexPrint("Salt+Plain (padded)", buf.data(), buf.size());

  // Now encrypt the salted data using three algorithms
  // Chaotic LFSR mixing
  {
    ChaoticLFSR32 lfsr((uint32_t)mk.lfsrSeed, mk.tinkerbellKey, 0x0029u);
    lfsr.xorBuffer(buf.data(), buf.size());
    if (verbose) hexPrint("After ChaoticLFSR", buf.data(), buf.size());
  }

  // Tinkerbell mixing
  {
    Tinkerbell tk(mk.tinkerbellKey);
    tk.xorBitwise(buf.data(), buf.size());
    if (verbose) hexPrint("After Tinkerbell", buf.data(), buf.size());
  }

  // Transposition
  {
    applyTransposition(buf.data(), grid, mk.transpositionKey, PermuteMode::Forward);
    if (verbose) hexPrint("After Transposition", buf.data(), buf.size());
  }
  if (verbose) hexPrint("After Encryption (with salt)", buf.data(), buf.size());

  const size_t headerLen = 8;
  const size_t nonceLen = includeNonceExt ? 4 : 0;
  const size_t tagLen = HMAC_TAG_LEN;

  // Reserve space for header + nonce + encrypted data + tag
  const size_t macInLen = headerLen + nonceLen + buf.size();
  packet.resize(macInLen);

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

  // Copy the encrypted data (which already includes salt)
  memcpy(p + headerLen + nonceLen, buf.data(), buf.size());

  // Append tag after MAC computation
  packet.resize(macInLen + tagLen);

  // Compute HMAC over header + nonce + encrypted & salted data using base HMAC key
  if (!hmac_sha256_trunc(baseKeys.hmacKey, 32,
                         packet.data(), macInLen,
                         packet.data() + macInLen, tagLen)) {
    memset(packet.data() + macInLen, 0, tagLen);
  }
  
  if (verbose) {
    Serial.printf("[ESP32] HMAC computed over %u bytes (including salt) using base HMAC key (nonce=0x%08X)\n", 
                  (unsigned)macInLen, nonce);
    hexPrint("Base HMAC key", baseKeys.hmacKey, 16);
    hexPrint("HMAC input", packet.data(), macInLen);
    hexPrint("HMAC tag", packet.data() + macInLen, tagLen);
  }
}

// State Machine
void handle_communication_state() {
  static unsigned long lastStateChange = 0;
  
  switch (currentState) {
    case STATE_INIT_NVS: {
      printStatus("INIT_NVS");
      esp_err_t nvs_err = nvs_flash_init();
      if (nvs_err == ESP_ERR_NVS_NO_FREE_PAGES || nvs_err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase();
        nvs_err = nvs_flash_init();
      }
      if (nvs_err == ESP_OK) {
        Serial.println("✓ NVS initialized");
        currentState = STATE_CONNECT_WIFI;
      } else {
        Serial.printf("✗ NVS failed: %s\n", esp_err_to_name(nvs_err));
        currentState = STATE_ERROR;
      }
      break;
    }
    
    case STATE_CONNECT_WIFI: {
      printStatus("CONNECT_WIFI");
      if (WiFi.status() != WL_CONNECTED) {
        // Start an attempt if not in progress
        if (!wifiAttemptInProgress) {
          Serial.printf("Connecting to %s\n", WIFI_SSID);
          WiFi.disconnect(true, true);
          delay(100);
          WiFi.mode(WIFI_STA);
          WiFi.setSleep(false);
          WiFi.persistent(false);
          WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
          wifiAttemptInProgress = true;
          wifiAttemptStartMs = millis();
        }
        // Timeout handling (15s)
        if (wifiAttemptInProgress && (millis() - wifiAttemptStartMs > 15000)) {
          Serial.println("WiFi connect timeout - retrying");
          wifiAttemptInProgress = false;
          retryCount++;
          delay(200);
        }
      } else {
        Serial.printf("✓ WiFi connected! IP: %s\n", WiFi.localIP().toString().c_str());
        wifiAttemptInProgress = false;
        currentState = STATE_CHECK_PUBLIC_KEY;
      }
      break;
    }
    
    case STATE_CHECK_PUBLIC_KEY: {
      printStatus("CHECK_PUBLIC_KEY");
      if (load_public_key_nvs(gPublicKey)) {
        publicKeyLoaded = true;
        Serial.println("✓ Public key loaded from NVS");
        currentState = STATE_GENERATE_MASTER_KEY;
      } else {
        Serial.println("No public key in NVS, fetching from server");
        currentState = STATE_GET_PUBLIC_KEY;
      }
      break;
    }
    
    case STATE_GET_PUBLIC_KEY: {
      printStatus("GET_PUBLIC_KEY");
      if (http_get_public_key()) {
        retryCount = 0;
        currentState = STATE_GENERATE_MASTER_KEY;
      } else {
        retryCount++;
        if (retryCount < MAX_RETRIES) {
          Serial.printf("Retry %d/%d for public key\n", retryCount, MAX_RETRIES);
          delay(2000);
        } else {
          Serial.println("Failed to get public key after max retries");
          currentState = STATE_ERROR;
        }
      }
      break;
    }
    
    case STATE_GENERATE_MASTER_KEY: {
      printStatus("GENERATE_MASTER_KEY");
      currentState = STATE_ENCRYPT_MASTER_KEY;
      break;
    }
    
    case STATE_ENCRYPT_MASTER_KEY: {
      printStatus("ENCRYPT_MASTER_KEY");
      if (generate_and_encrypt_master_key()) {
        retryCount = 0;
        currentState = STATE_DERIVE_SYMMETRIC;
        Serial.println("✓ Master key exchange completed");
      } else {
        retryCount++;
        if (retryCount < MAX_RETRIES) {
          Serial.printf("Retry %d/%d for master key\n", retryCount, MAX_RETRIES);
          delay(3000);
        } else {
          Serial.println("Master key exchange failed after max retries");
          currentState = STATE_ERROR;
        }
      }
      break;
    }
    
    case STATE_DERIVE_SYMMETRIC: {
      printStatus("DERIVE_SYMMETRIC");
      if (derive_symmetric_keys()) {
        Serial.println("✓ Symmetric keys ready - starting health data transmission");
        lastHealthSend = millis();
        currentState = STATE_SEND_HEALTH_DATA;
      } else {
        Serial.println("Symmetric key derivation failed");
        currentState = STATE_ERROR;
      }
      break;
    }
    
    case STATE_SEND_HEALTH_DATA: {
      printStatus("SEND_HEALTH_DATA");
      if (millis() - lastHealthSend >= HEALTH_DATA_INTERVAL_MS) {
        if (encrypt_and_send_health_data()) {
          retryCount = 0;
          lastHealthSend = millis();
        } else {
          retryCount++;
          if (retryCount >= MAX_RETRIES) {
            Serial.println("Health data transmission failed after max retries");
            currentState = STATE_ERROR;
          }
        }
      }
      break;
    }
    
    case STATE_ERROR: {
      printStatus("ERROR");
      Serial.println("ERROR state - restart device or check connectivity");
      delay(5000);
      break;
    }
  }
}

static bool derive_symmetric_keys() {
  Serial.println("Loading master key from NVS and deriving symmetric keys...");
  
  // Load master key from NVS
  nvs_handle_t handle;
  esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READONLY, &handle);
  if (err != ESP_OK) {
    Serial.printf("Failed to open NVS: %s\n", esp_err_to_name(err));
    return false;
  }
  
  size_t required_size = 32;
  uint8_t masterKey[32];
  err = nvs_get_blob(handle, NVS_MASTER_KEY_KEY, masterKey, &required_size);
  nvs_close(handle);
  
  if (err != ESP_OK) {
    Serial.printf("Failed to load master key from NVS: %s\n", esp_err_to_name(err));
    return false;
  }
  
  if (required_size != 32) {
    Serial.printf("Invalid master key size: %u (expected 32)\n", (unsigned)required_size);
    return false;
  }
  
  hexPrint("Loaded master key from NVS", masterKey, 32);
  
  if (!deriveKeys(masterKey, 32, gBaseKeys)) {
    Serial.println("Failed to derive symmetric keys");
    memset(masterKey, 0, 32);
    return false;
  }
  
  hexPrint("Derived HMAC key", gBaseKeys.hmacKey, 32);
  
  masterKeyReady = true;
  Serial.println("✓ Symmetric keys derived successfully");
  
  // Clear sensitive data
  memset(masterKey, 0, 32);
  
  return true;
}

void setup() {
  Serial.begin(115200);
  delay(1000);
  
  Serial.println("=== XenoCipher ESP32 Client ===");
  Serial.printf("Chip: %s Rev %d\n", ESP.getChipModel(), ESP.getChipRevision());
  Serial.printf("Flash: %u KB\n", ESP.getFlashChipSize() / 1024);
  Serial.printf("Free heap: %u bytes\n", ESP.getFreeHeap());
  
  // Initialize WiFi event handler
  WiFi.onEvent(onWiFiEvent);
  
  Serial.println("Starting communication state machine...");
}

void loop() {
  handle_communication_state();
  delay(100);
}
