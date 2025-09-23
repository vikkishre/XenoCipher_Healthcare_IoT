#include "entropy.h"
#include <Arduino.h>
#include <esp_timer.h>
#include <esp_system.h>
#include <esp_wifi.h>       // for esp_read_mac (if using Arduino framework)
#include <mbedtls/sha256.h>
#include <mbedtls/md.h>
#include <string.h>
#include <stdlib.h>

// Secure zero helper
static void secure_zero(void *p, size_t n) {
#if defined(__STDC_LIB_EXT1__)
  memset_s(p, n, 0, n);
#else
  volatile uint8_t *q = (volatile uint8_t *)p;
  while (n--) *q++ = 0;
#endif
}

// Helper: feed bytes into SHA-256 (incrementally)
static void sha256_update_bytes(mbedtls_sha256_context *ctx, const void *buf, size_t len) {
  mbedtls_sha256_update_ret(ctx, (const unsigned char*)buf, len);
}

// Read MAC address into 6 bytes (esp_read_mac is reliable)
static void get_mac(uint8_t mac[6]) {
  // On ESP-IDF / Arduino, esp_read_mac is available
#ifdef ESP32
  // ESP_MAC_WIFI_STA returns station MAC
  esp_read_mac(mac, ESP_MAC_WIFI_STA);
#else
  // Fallback: try WiFi.macAddress() parse (less preferred)
  String s = WiFi.macAddress();
  int vals[6] = {0};
  if (sscanf(s.c_str(), "%x:%x:%x:%x:%x:%x", &vals[0], &vals[1], &vals[2], &vals[3], &vals[4], &vals[5]) == 6) {
    for (int i=0;i<6;i++) mac[i] = (uint8_t)vals[i];
  } else {
    // fallback to esp_random bits
    uint32_t r1 = esp_random();
    uint32_t r2 = esp_random();
    mac[0] = r1 & 0xFF; mac[1] = (r1>>8)&0xFF; mac[2] = (r1>>16)&0xFF;
    mac[3] = (r1>>24)&0xFF; mac[4] = r2 & 0xFF; mac[5] = (r2>>8)&0xFF;
  }
#endif
}

bool gatherMasterKey(uint8_t out32[32], EntropyReport *report) {
  if (!out32) return false;

  // Initialize SHA-256 (streaming)
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  if (mbedtls_sha256_starts_ret(&ctx, 0) != 0) {
    mbedtls_sha256_free(&ctx);
    return false;
  }

  EntropyReport localReport;
  memset(&localReport, 0, sizeof(localReport));

  // 1) High-res time
  localReport.time_us = (uint64_t) esp_timer_get_time();
  sha256_update_bytes(&ctx, &localReport.time_us, sizeof(localReport.time_us));

  // 2) Hardware RNG samples (collect several short bursts)
  for (int i = 0; i < 8; ++i) {
    uint32_t r = esp_random();
    localReport.rng_samples[i] = r;
    sha256_update_bytes(&ctx, &r, sizeof(r));
    // tiny random delay to decorrelate
    delayMicroseconds( (r & 0x1F) + 1 );
  }

  // 3) MAC address
  get_mac(localReport.mac);
  sha256_update_bytes(&ctx, localReport.mac, sizeof(localReport.mac));

  // 4) Small structural values: free heap and stack pointer
  localReport.free_heap = esp_get_free_heap_size();
  // get an approximation of stack pointer (address of local variable)
  uint32_t sp;
  volatile int stack_probe = 0;
  sp = (uint32_t)&stack_probe;
  localReport.stack_ptr = sp;
  sha256_update_bytes(&ctx, &localReport.free_heap, sizeof(localReport.free_heap));
  sha256_update_bytes(&ctx, &localReport.stack_ptr, sizeof(localReport.stack_ptr));

  // 5) Analog noise sampling from multiple pins (GPIO34, GPIO35, GPIO32) - input-only pins
  const int analogPins[] = {34, 35, 32};
  const int numPins = sizeof(analogPins) / sizeof(analogPins[0]);
  for (int i = 0; i < 16; ++i) {
    // choose pin pseudo-randomly from previous RNG & time
    int pin = analogPins[(i + (localReport.rng_samples[i % 8] & 0x7)) % numPins];
    // configure ADC read; analogRead works on Arduino core
    uint16_t v = (uint16_t) analogRead(pin);
    localReport.analog_samples[i] = v;
    sha256_update_bytes(&ctx, &v, sizeof(v));
    // small variable spin to add jitter
    uint32_t spin = (esp_random() & 0x3F) + 1;
    for (volatile uint32_t k = 0; k < spin; ++k) { __asm__ volatile("nop"); }
  }

  // 6) Jitter samples: micros() deltas with tiny randomized spin in between
  for (int i = 0; i < 16; ++i) {
    uint32_t t0 = micros();
    // tiny randomized busy-loop
    uint32_t spin = (esp_random() & 0xFF);
    for (volatile uint32_t k = 0; k < spin; ++k) { __asm__ volatile("nop"); }
    uint32_t t1 = micros();
    uint32_t delta = t1 - t0;
    localReport.jitter_samples[i] = delta;
    sha256_update_bytes(&ctx, &delta, sizeof(delta));
  }

  // 7) Additional RNG mixing loop to harvest additional hardware entropy
  for (int i = 0; i < 4; ++i) {
    uint32_t r1 = esp_random();
    uint32_t r2 = esp_random();
    sha256_update_bytes(&ctx, &r1, sizeof(r1));
    sha256_update_bytes(&ctx, &r2, sizeof(r2));
  }

  // finalize SHA-256
  uint8_t digest[32];
  if (mbedtls_sha256_finish_ret(&ctx, digest) != 0) {
    mbedtls_sha256_free(&ctx);
    secure_zero(&localReport, sizeof(localReport));
    return false;
  }
  mbedtls_sha256_free(&ctx);

  // 8) Whitening / Derivation: HMAC-SHA256(digest, "XENO-MK-WHITE") => final key
  // This avoids using the raw digest directly and stretches it cryptographically.
  {
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!info) { secure_zero(digest, sizeof(digest)); secure_zero(&localReport, sizeof(localReport)); return false; }
    mbedtls_md_context_t hctx;
    mbedtls_md_init(&hctx);
    if (mbedtls_md_setup(&hctx, info, 1) != 0) { mbedtls_md_free(&hctx); secure_zero(digest, sizeof(digest)); secure_zero(&localReport, sizeof(localReport)); return false; }
    // Use digest as HMAC key and a fixed label as message
    const uint8_t label[] = "XENO-MK-WHITE-v1";
    if (mbedtls_md_hmac_starts(&hctx, digest, sizeof(digest)) != 0) { mbedtls_md_free(&hctx); secure_zero(digest, sizeof(digest)); secure_zero(&localReport, sizeof(localReport)); return false; }
    if (mbedtls_md_hmac_update(&hctx, label, sizeof(label)-1) != 0) { mbedtls_md_free(&hctx); secure_zero(digest, sizeof(digest)); secure_zero(&localReport, sizeof(localReport)); return false; }
    if (mbedtls_md_hmac_finish(&hctx, out32) != 0) { mbedtls_md_free(&hctx); secure_zero(digest, sizeof(digest)); secure_zero(&localReport, sizeof(localReport)); return false; }
    mbedtls_md_free(&hctx);
  }

  // Zero sensitive temporaries
  secure_zero(digest, sizeof(digest));

  // Optionally return non-secret report for diagnostics
  if (report) {
    // copy a limited, non-secret subset
    report->time_us = localReport.time_us;
    for (int i = 0; i < 8; ++i) report->rng_samples[i] = localReport.rng_samples[i];
    memcpy(report->mac, localReport.mac, 6);
    for (int i = 0; i < 16; ++i) report->analog_samples[i] = localReport.analog_samples[i];
    for (int i = 0; i < 16; ++i) report->jitter_samples[i] = localReport.jitter_samples[i];
    report->stack_ptr = localReport.stack_ptr;
    report->free_heap = localReport.free_heap;
  }

  // final cleanup
  secure_zero(&localReport, sizeof(localReport));
  return true;
}

void printEntropySummary(const EntropyReport *report) {
  if (!report) return;
  Serial.printf("Entropy time_us: %llu\n", (unsigned long long)report->time_us);
  Serial.print("Entropy MAC: ");
  for (int i = 0; i < 6; ++i) {
    Serial.printf("%02X", report->mac[i]);
    if (i < 5) Serial.print(":");
  }
  Serial.println();
  Serial.print("Entropy analog[0..3]: ");
  for (int i = 0; i < 4; ++i) Serial.printf("%u ", report->analog_samples[i]);
  Serial.println();
  Serial.print("Entropy jitter[0..3]: ");
  for (int i = 0; i < 4; ++i) Serial.printf("%u ", report->jitter_samples[i]);
  Serial.println();
}