#include <Arduino.h>
#include <WiFi.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include <nvs_flash.h>
#include <esp_random.h>
#include <esp_timer.h>
#include <vector>

#include "crypto_kdf.h"
#include "lfsr.h"
#include "tinkerbell.h"
#include "transposition.h"
#include "hmac.h"
#include "entropy.h"
#include "ntru.h"

#ifndef HMAC_TAG_LEN
#define HMAC_TAG_LEN 16
#endif

#define VERSION_BASE 0x01
#define VERSION_NONCE_EXT 0x81

// === CONFIGURATION - UPDATE THESE VALUES ===
#define SERVER_URL "http://10.244.62.103:8081"  // ← THIS IS YOUR CORRECT LOCAL IP
#define WIFI_SSID "Galaxy M322E19"
#define WIFI_PASSWORD "yvhh6733"

// Communication timing
#define HEALTH_DATA_INTERVAL_MS 10000
#define CONNECTION_TIMEOUT_MS 10000
#define MAX_RETRIES 3

// Debug level
#ifndef DEBUG_LEVEL
#define DEBUG_LEVEL 2
#endif

// Version info
#ifndef XENOCIPHER_VERSION_MAJOR
#define XENOCIPHER_VERSION_MAJOR 1
#define XENOCIPHER_VERSION_MINOR 0
#define XENOCIPHER_VERSION_PATCH 0
#endif

// Memory optimization
#define JSON_DOC_SIZE 2048
#define MAX_RESPONSE_SIZE 512
#define MAX_HEALTH_DATA_SIZE 64

// State machine for communication flow
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

static CommState currentState = STATE_INIT_NVS;
static bool masterKeyReady = false;
static bool publicKeyLoaded = false;
static uint32_t lastHealthSend = 0;
static int healthSendCount = 0;
static int retryCount = 0;

// Global keys and buffers - use pointers to avoid large stack allocations
static DerivedKeys* gBaseKeys = nullptr;
static uint8_t* gMasterKey = nullptr;
static std::vector<uint8_t> gPublicKey;

struct SaltMeta {
    uint16_t pos;
    uint8_t len;
};

// WiFi event handler
void WiFiEvent(WiFiEvent_t event, WiFiEventInfo_t info) {
    switch(event) {
        case ARDUINO_EVENT_WIFI_STA_START:
            Serial.println("WiFi STA Started");
            break;
        case ARDUINO_EVENT_WIFI_STA_CONNECTED:
            Serial.println("Connected to AP");
            break;
        case ARDUINO_EVENT_WIFI_STA_GOT_IP:
            Serial.printf("Got IP: %s\n", IPAddress(info.got_ip.ip_info.ip.addr).toString().c_str());
            break;
        case ARDUINO_EVENT_WIFI_STA_DISCONNECTED:
            Serial.println("Disconnected from AP");
            Serial.printf("Reason: %d\n", info.wifi_sta_disconnected.reason);
            break;
        default:
            break;
    }
}

// === MEMORY MANAGEMENT ===
void init_memory() {
    gBaseKeys = new DerivedKeys();
    gMasterKey = new uint8_t[32]();
    
    if (!gBaseKeys || !gMasterKey) {
        Serial.println("FATAL: Memory allocation failed!");
        while(1) delay(1000);
    }
}

void cleanup_memory() {
    if (gMasterKey) {
        memset(gMasterKey, 0, 32);
        delete[] gMasterKey;
        gMasterKey = nullptr;
    }
    
    if (gBaseKeys) {
        delete gBaseKeys;
        gBaseKeys = nullptr;
    }
    
    gPublicKey.clear();
    gPublicKey.shrink_to_fit();
}

// === UTILITY FUNCTIONS ===
static void printStatus(const char* stateName) {
  Serial.printf("[%.3f] STATE: %s | WiFi: %s | MasterKey: %s | HealthSent: %d\n",
    millis() / 1000.0, stateName,
    WiFi.status() == WL_CONNECTED ? "OK" : "DOWN",
    masterKeyReady ? "READY" : "PENDING",
    healthSendCount);
}

static void hexPrint(const char* label, const uint8_t* data, size_t n) {
  if (DEBUG_LEVEL < 2 || n == 0) return;
  
  Serial.printf("%s (%u): ", label, (unsigned)n);
  size_t print_len = n > 32 ? 32 : n; // Limit output
  for (size_t i = 0; i < print_len; ++i) {
    Serial.printf("%02X", data[i]);
  }
  if (n > 32) Serial.print("...");
  Serial.println();
}

// === NVS STORAGE FUNCTIONS ===
static bool store_public_key_nvs(const std::vector<uint8_t>& pub_bytes) {
  nvs_handle_t handle;
  esp_err_t err = nvs_open("xenocipher", NVS_READWRITE, &handle);
  if (err != ESP_OK) {
    Serial.printf("NVS open failed: %s\n", esp_err_to_name(err));
    return false;
  }
  
  err = nvs_set_blob(handle, "ntru_pub", pub_bytes.data(), pub_bytes.size());
  nvs_close(handle);
  
  if (err == ESP_OK) {
    Serial.printf("✓ Stored public key (%u bytes)\n", (unsigned)pub_bytes.size());
    return true;
  } else {
    Serial.printf("NVS set_blob failed: %s\n", esp_err_to_name(err));
    return false;
  }
}

static bool load_public_key_nvs(std::vector<uint8_t>& pub_bytes) {
  nvs_handle_t handle;
  esp_err_t err = nvs_open("xenocipher", NVS_READONLY, &handle);
  if (err != ESP_OK) {
    return false;
  }
  
  size_t required_size = 0;
  err = nvs_get_blob(handle, "ntru_pub", nullptr, &required_size);
  if (err != ESP_OK || required_size == 0) {
    nvs_close(handle);
    return false;
  }
  
  pub_bytes.resize(required_size);
  err = nvs_get_blob(handle, "ntru_pub", pub_bytes.data(), &required_size);
  nvs_close(handle);
  
  return err == ESP_OK;
}

// === HEX PARSING ===
static bool parse_hex_string(const char* hex_str, std::vector<uint8_t>& out) {
  out.clear();
  
  size_t len = strlen(hex_str);
  if (len % 2 != 0) {
    return false;
  }
  
  out.reserve(len / 2);
  for (size_t i = 0; i < len; i += 2) {
    char hex_byte[3] = {hex_str[i], hex_str[i+1], '\0'};
    char* endptr;
    long byte_val = strtol(hex_byte, &endptr, 16);
    
    if (endptr == hex_byte || *endptr != '\0') {
      return false;
    }
    
    out.push_back((uint8_t)byte_val);
  }
  
  return true;
}

// === HTTP CLIENT FUNCTIONS ===
static bool http_get_public_key() {
  if (WiFi.status() != WL_CONNECTED) {
    return false;
  }

  HTTPClient http;
  char url[128];
  snprintf(url, sizeof(url), "%s/public-key", SERVER_URL);
  
  http.begin(url);
  http.setTimeout(CONNECTION_TIMEOUT_MS);
  
  int httpCode = http.GET();
  if (httpCode == HTTP_CODE_OK) {
    WiFiClient* stream = http.getStreamPtr();
    
    StaticJsonDocument<JSON_DOC_SIZE> doc;
    DeserializationError error = deserializeJson(doc, *stream);
    
    if (error) {
      http.end();
      return false;
    }
    
    const char* pubKeyStr = doc["publicKey"];
    if (pubKeyStr && strncmp(pubKeyStr, "PUBHEX:", 7) == 0) {
      std::vector<uint8_t> pubBytes;
      if (parse_hex_string(pubKeyStr + 7, pubBytes)) {
        if (store_public_key_nvs(pubBytes)) {
          gPublicKey = std::move(pubBytes);
          publicKeyLoaded = true;
          http.end();
          return true;
        }
      }
    }
  }
  
  http.end();
  return false;
}

static bool http_post_encrypted_data(const char* endpoint, const uint8_t* data, size_t data_len, const char* prefix) {
  if (WiFi.status() != WL_CONNECTED) {
    return false;
  }

  HTTPClient http;
  char url[128];
  snprintf(url, sizeof(url), "%s%s", SERVER_URL, endpoint);
  
  http.begin(url);
  http.addHeader("Content-Type", "application/json");
  http.setTimeout(CONNECTION_TIMEOUT_MS);
  
  // Calculate required buffer size
  size_t prefix_len = strlen(prefix);
  size_t hex_len = data_len * 2;
  size_t json_len = prefix_len + hex_len + 20;
  
  String jsonPayload;
  jsonPayload.reserve(json_len);
  jsonPayload = "{\"data\":\"";
  jsonPayload += prefix;
  
  // Convert data to hex
  for (size_t i = 0; i < data_len; ++i) {
    char hex[3];
    snprintf(hex, sizeof(hex), "%02X", data[i]);
    jsonPayload += hex;
  }
  jsonPayload += "\"}";
  
  int httpCode = http.POST(jsonPayload);
  bool success = (httpCode == HTTP_CODE_OK);
  
  http.end();
  return success;
}

// === XENOCIPHER PIPELINE FUNCTIONS ===
static bool insertSalt(const uint8_t* plain, size_t plen, const uint8_t* salt, uint8_t slen,
                      uint16_t salt_pos, std::vector<uint8_t>& out) {
  out.clear();
  out.reserve(plen + slen);
  
  uint16_t pos = salt_pos > plen ? plen : salt_pos;
  out.insert(out.end(), plain, plain + pos);
  out.insert(out.end(), salt, salt + slen);
  out.insert(out.end(), plain + pos, plain + plen);
  
  return true;
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

static void writeHeader(uint8_t* hdr, uint8_t version, uint8_t salt_len,
                       uint16_t salt_pos, uint16_t payload_len,
                       uint8_t rows, uint8_t cols) {
  hdr[0] = version;
  hdr[1] = salt_len;
  hdr[2] = salt_pos & 0xFF;
  hdr[3] = (salt_pos >> 8) & 0xFF;
  hdr[4] = payload_len & 0xFF;
  hdr[5] = (payload_len >> 8) & 0xFF;
  hdr[6] = rows;
  hdr[7] = cols;
}

static bool pipelineEncryptPacket(const DerivedKeys& baseKeys, uint32_t nonce,
                                 const uint8_t* data, size_t data_len,
                                 const GridSpec& grid, uint8_t salt_len,
                                 uint16_t salt_pos, uint16_t payload_len,
                                 std::vector<uint8_t>& packet) {
  MessageKeys mk;
  if (!deriveMessageKeys(baseKeys, nonce, mk)) {
    return false;
  }

  // Pad data to grid size
  size_t padded_size = grid.rows * grid.cols;
  std::vector<uint8_t> padded(padded_size, 0);
  size_t copy_len = data_len > padded_size ? padded_size : data_len;
  memcpy(padded.data(), data, copy_len);

  // Apply ChaoticLFSR
  ChaoticLFSR32 lfsr((uint32_t)mk.lfsrSeed, mk.tinkerbellKey, 0x0029u);
  lfsr.xorBuffer(padded.data(), padded.size());

  // Apply Tinkerbell
  Tinkerbell tk(mk.tinkerbellKey);
  tk.xorBitwise(padded.data(), padded.size());

  // Apply Transposition
  applyTransposition(padded.data(), grid, mk.transpositionKey, PermuteMode::Forward);

  // Build packet
  const size_t header_len = 8;
  const size_t nonce_len = 4;
  const size_t tag_len = HMAC_TAG_LEN;
  
  packet.resize(header_len + nonce_len + padded_size + tag_len);
  uint8_t* p = packet.data();

  writeHeader(p, VERSION_NONCE_EXT, salt_len, salt_pos, payload_len,
              grid.rows, grid.cols);

  // Add nonce
  p[8] = nonce >> 24;
  p[9] = (nonce >> 16) & 0xFF;
  p[10] = (nonce >> 8) & 0xFF;
  p[11] = nonce & 0xFF;

  // Copy encrypted data
  memcpy(p + header_len + nonce_len, padded.data(), padded_size);

  // Calculate HMAC
  return hmac_sha256_trunc(baseKeys.hmacKey, sizeof(baseKeys.hmacKey),
                          packet.data(), header_len + nonce_len + padded_size,
                          p + header_len + nonce_len + padded_size, tag_len);
}

// === NTRU MASTER KEY FUNCTIONS ===
static bool generate_and_encrypt_master_key() {
  if (!gMasterKey) return false;
  
  // Generate master key
  EntropyReport er{};
  if (!gatherMasterKey(gMasterKey, &er)) {
    return false;
  }

  // Encrypt with NTRU
  NTRU ntru;
  Poly m, e, h;
  
  // Convert master key to polynomial
  std::vector<uint8_t> masterBytes(gMasterKey, gMasterKey + 32);
  NTRU::bytes_to_poly(masterBytes, m, 32);
  
  // Load public key
  if (gPublicKey.empty()) return false;
  
  for (int i = 0; i < NTRU_N; ++i) {
    h.coeffs[i] = (gPublicKey[i * 2] << 8) | gPublicKey[i * 2 + 1];
  }
  
  // Encrypt
  ntru.encrypt(m, h, e);
  
  // Convert to bytes
  std::vector<uint8_t> encryptedKey(NTRU_N * 2);
  for (int i = 0; i < NTRU_N; ++i) {
    encryptedKey[i * 2] = e.coeffs[i] >> 8;
    encryptedKey[i * 2 + 1] = e.coeffs[i] & 0xFF;
  }
  
  // Send to server
  bool success = http_post_encrypted_data("/master-key", encryptedKey.data(), encryptedKey.size(), "ENCKEY:");
  
  // Clear sensitive data
  memset(gMasterKey, 0, 32);
  
  return success;
}

static bool derive_symmetric_keys() {
  if (!gMasterKey || !gBaseKeys) return false;
  
  // Regenerate master key
  EntropyReport er{};
  if (!gatherMasterKey(gMasterKey, &er)) {
    return false;
  }
  
  if (!deriveKeys(gMasterKey, 32, *gBaseKeys)) {
    return false;
  }
  
  memset(gMasterKey, 0, 32);
  masterKeyReady = true;
  return true;
}

// === HEALTH DATA ===
static void generate_health_data(char* buffer, size_t buffer_size) {
  uint32_t timestamp = millis();
  uint8_t heart_rate = 60 + (timestamp / 60000) % 40;
  uint8_t spo2 = 95 + (timestamp / 300000) % 5;
  uint16_t steps = (timestamp / 1000) * 2;
  
  snprintf(buffer, buffer_size, "HR-%u SPO2-%u STEPS-%u", heart_rate, spo2, steps);
}

static bool encrypt_and_send_health_data() {
  if (!gBaseKeys) return false;
  
  char health_data[MAX_HEALTH_DATA_SIZE];
  generate_health_data(health_data, sizeof(health_data));
  
  size_t data_len = strlen(health_data);
  
  // Generate salt - fix narrowing conversion
  uint32_t rand_val1 = esp_random();
  uint32_t rand_val2 = esp_random();
  uint8_t salt[2] = {
    static_cast<uint8_t>(rand_val1 & 0xFF),
    static_cast<uint8_t>((rand_val2 >> 8) & 0xFF)
  };
  uint16_t salt_pos = data_len; // Insert at end
  
  // Insert salt
  std::vector<uint8_t> salted;
  if (!insertSalt((const uint8_t*)health_data, data_len, salt, sizeof(salt), salt_pos, salted)) {
    return false;
  }
  
  // Select grid
  GridSpec grid = selectGrid(salted.size());
  
  // Encrypt
  uint32_t nonce = esp_random();
  std::vector<uint8_t> packet;
  
  if (!pipelineEncryptPacket(*gBaseKeys, nonce, salted.data(), salted.size(),
                            grid, sizeof(salt), salt_pos, data_len, packet)) {
    return false;
  }
  
  // Send to server
  return http_post_encrypted_data("/health-data", packet.data(), packet.size(), "ENC_DATA:");
}

// === STATE MACHINE ===
void handle_communication_state() {
  static uint32_t last_state_change = 0;
  esp_err_t nvs_err = ESP_OK; // Move variable declaration outside switch
  
  switch (currentState) {
    case STATE_INIT_NVS: {
      printStatus("INIT_NVS");
      init_memory();
      
      nvs_err = nvs_flash_init();
      if (nvs_err == ESP_ERR_NVS_NO_FREE_PAGES || nvs_err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase();
        nvs_err = nvs_flash_init();
      }
      
      currentState = (nvs_err == ESP_OK) ? STATE_CONNECT_WIFI : STATE_ERROR;
      break;
    }
      
    case STATE_CONNECT_WIFI: {
      printStatus("CONNECT_WIFI");
      
      if (WiFi.status() != WL_CONNECTED) {
        WiFi.disconnect(true);
        delay(100);
        WiFi.mode(WIFI_STA);
        WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
        
        for (int i = 0; i < 20 && WiFi.status() != WL_CONNECTED; ++i) {
          delay(500);
        }
      }
      
      currentState = (WiFi.status() == WL_CONNECTED) ? STATE_CHECK_PUBLIC_KEY : STATE_ERROR;
      break;
    }
      
    case STATE_CHECK_PUBLIC_KEY: {
      printStatus("CHECK_PUBLIC_KEY");
      
      if (load_public_key_nvs(gPublicKey)) {
        publicKeyLoaded = true;
        currentState = STATE_GENERATE_MASTER_KEY;
      } else {
        currentState = STATE_GET_PUBLIC_KEY;
      }
      break;
    }
      
    case STATE_GET_PUBLIC_KEY: {
      printStatus("GET_PUBLIC_KEY");
      
      if (http_get_public_key()) {
        retryCount = 0;
        currentState = STATE_GENERATE_MASTER_KEY;
      } else if (++retryCount < MAX_RETRIES) {
        delay(2000);
      } else {
        currentState = STATE_ERROR;
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
      } else if (++retryCount < MAX_RETRIES) {
        delay(3000);
      } else {
        currentState = STATE_ERROR;
      }
      break;
    }
      
    case STATE_DERIVE_SYMMETRIC: {
      printStatus("DERIVE_SYMMETRIC");
      
      if (derive_symmetric_keys()) {
        lastHealthSend = millis();
        currentState = STATE_SEND_HEALTH_DATA;
      } else {
        currentState = STATE_ERROR;
      }
      break;
    }
      
    case STATE_SEND_HEALTH_DATA: {
      printStatus("SEND_HEALTH_DATA");
      
      if (millis() - lastHealthSend >= HEALTH_DATA_INTERVAL_MS) {
        if (encrypt_and_send_health_data()) {
          healthSendCount++;
          lastHealthSend = millis();
        } else if (++retryCount >= MAX_RETRIES) {
          currentState = STATE_ERROR;
        }
      }
      break;
    }
      
    case STATE_ERROR: {
      printStatus("ERROR");
      delay(5000);
      break;
    }
  }
}

void setup() {
  Serial.begin(115200);
  delay(2000);
  
  WiFi.onEvent(WiFiEvent);
  
  Serial.printf("\n=== XenoCipher Healthcare ESP32 ===\n");
  Serial.printf("Free heap: %u bytes\n", ESP.getFreeHeap());
  
  currentState = STATE_INIT_NVS;
}

void loop() {
  handle_communication_state();
  delay(50);
}