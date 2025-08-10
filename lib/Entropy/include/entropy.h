/**
 * entropy.h - Collects multiple entropy sources and returns a 32-byte master key.
 *
 * Sources collected (mixing order, incremental SHA-256):
 *  - esp_timer_get_time() (high-res time)
 *  - esp_random() samples (hardware RNG)
 *  - Device MAC address (esp_read_mac)
 *  - Analog noise from multiple floating pins (configurable)
 *  - FreeRTOS/loop scheduling jitter (micros() deltas)
 *  - stack pointer, heap free, cpu cycle counter
 *
 * Output:
 *  - 32-byte master key (SHA-256-derived + optional whitening)
 *
 * EntropyReport contains non-sensitive diagnostics (does NOT contain the final key).
 * Use report only for debugging; avoid transmitting it in production.
 */
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  uint64_t time_us;
  uint32_t rng_samples[8];
  uint8_t mac[6];
  uint16_t analog_samples[16];
  uint32_t jitter_samples[16];
  uint32_t stack_ptr;
  size_t free_heap;
} EntropyReport;

/**
 * Gather a 32-byte master key. Returns true on success.
 * - out32 must be 32 bytes.
 * - report is optional and will be filled with diagnostic values (no secret key material).
 *
 * Notes:
 * - This function mixes many sources and runs quickly (~a few ms to tens of ms).
 * - Call once at device provisioning/startup and store master key securely (NVS + flash encryption).
 */
bool gatherMasterKey(uint8_t out32[32], EntropyReport *report /* optional, can be NULL */);

#ifdef __cplusplus
}
#endif
