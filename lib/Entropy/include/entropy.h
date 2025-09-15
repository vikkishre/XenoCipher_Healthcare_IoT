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

bool gatherMasterKey(uint8_t out32[32], EntropyReport *report /* optional, can be NULL */);

#ifdef __cplusplus
}
#endif