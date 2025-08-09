/**
 * entropy.h - Collects multiple entropy sources and returns a 32-byte master key.
 * Sources:
 *  - esp_timer_get_time() (high-res time)
 *  - esp_random() (multiple samples)
 *  - Device MAC address
 *  - Analog noise from floating pin (GPIO34)
 *  - FreeRTOS scheduling jitter (micro-second deltas)
 * Output:
 *  - 32-byte SHA-256(master_entropy_blob)
 */
#pragma once
#include <stdint.h>
#include <stddef.h>

struct EntropyReport {
  uint64_t time_us;
  uint32_t rng_words[16];
  uint8_t mac[6];
  uint16_t analog_samples[16];
  uint32_t jitter[16];
};

bool gatherMasterKey(uint8_t out32[32], EntropyReport* report /* optional, can be nullptr */);
