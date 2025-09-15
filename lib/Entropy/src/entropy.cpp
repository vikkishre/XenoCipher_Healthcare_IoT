#include "../include/entropy.h"
#include <random>
#include <cstring>

bool gatherMasterKey(uint8_t out32[32], EntropyReport *report) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    // Generate 32-byte master key
    for (size_t i = 0; i < 32; ++i) {
        out32[i] = static_cast<uint8_t>(dis(gen));
    }

    // Fill report with dummy values (for server compatibility)
    if (report) {
        report->time_us = 0;
        for (int i = 0; i < 8; ++i) report->rng_samples[i] = dis(gen);
        for (int i = 0; i < 6; ++i) report->mac[i] = dis(gen);
        for (int i = 0; i < 16; ++i) report->analog_samples[i] = dis(gen) % 1024;
        for (int i = 0; i < 16; ++i) report->jitter_samples[i] = dis(gen) % 1000;
        report->stack_ptr = 0;
        report->free_heap = 0;
    }

    return true;
}  