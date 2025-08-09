#include "entropy.h"
#include <Arduino.h>
#include <esp_timer.h>
#include <esp_system.h>
#include <WiFi.h>
#include <mbedtls/sha256.h>

static void sha256(const uint8_t* data, size_t len, uint8_t out32[32]) {
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts_ret(&ctx, 0);
  mbedtls_sha256_update_ret(&ctx, data, len);
  mbedtls_sha256_finish_ret(&ctx, out32);
  mbedtls_sha256_free(&ctx);
}

// Try to read MAC from WiFi (works even if WiFi not connected)
static void getMac(uint8_t mac[6]) {
  String s = WiFi.macAddress(); // e.g., "24:0A:C4:12:34:56"
  int vals[6] = {0};
  if (sscanf(s.c_str(), "%x:%x:%x:%x:%x:%x", &vals[0], &vals[1], &vals[2], &vals[3], &vals[4], &vals[5]) == 6) {
    for (int i = 0; i < 6; i++) mac[i] = (uint8_t)vals[i];
  } else {
    // Fallback to esp_random if WiFi MAC fails
    uint32_t r1 = esp_random();
    uint32_t r2 = esp_random();
    mac[0] = (r1 >> 0) & 0xFF;
    mac[1] = (r1 >> 8) & 0xFF;
    mac[2] = (r1 >> 16) & 0xFF;
    mac[3] = (r1 >> 24) & 0xFF;
    mac[4] = (r2 >> 0) & 0xFF;
    mac[5] = (r2 >> 8) & 0xFF;
  }
}

bool gatherMasterKey(uint8_t out32[32], EntropyReport* report) {
  // Configure analog pin for noise (GPIO34 is input-only, floating on many dev boards)
  const int ANALOG_PIN = 34;
  pinMode(ANALOG_PIN, INPUT);

  EntropyReport local{};
  local.time_us = (uint64_t)esp_timer_get_time();

  for (int i = 0; i < 16; ++i) local.rng_words[i] = esp_random();

  getMac(local.mac);

  // Analog noise samples
  for (int i = 0; i < 16; ++i) {
    local.analog_samples[i] = (uint16_t)analogRead(ANALOG_PIN);
    delayMicroseconds(200 + (esp_random() & 0x3F)); // minor desync
  }

  // Jitter (difference of close micros() reads)
  for (int i = 0; i < 16; ++i) {
    uint32_t t0 = micros();
    // busy wait a tiny, random-ish time
    for (volatile int k = 0; k < (50 + (esp_random() & 0x1FF)); ++k) { /* spin */ }
    uint32_t t1 = micros();
    local.jitter[i] = t1 - t0;
  }

  // Build the entropy blob
  // Format: [time_us | rng_words | mac | analog_samples | jitter]
  // Sizes:   8        64          6     32                64   = 174 bytes
  uint8_t blob[192] = {0};
  size_t pos = 0;
  memcpy(blob + pos, &local.time_us, sizeof(local.time_us)); pos += sizeof(local.time_us);
  memcpy(blob + pos, local.rng_words, sizeof(local.rng_words)); pos += sizeof(local.rng_words);
  memcpy(blob + pos, local.mac, sizeof(local.mac)); pos += sizeof(local.mac);
  memcpy(blob + pos, local.analog_samples, sizeof(local.analog_samples)); pos += sizeof(local.analog_samples);
  memcpy(blob + pos, local.jitter, sizeof(local.jitter)); pos += sizeof(local.jitter);

  sha256(blob, pos, out32);

  if (report) *report = local;
  return true;
}
