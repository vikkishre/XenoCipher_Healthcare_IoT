#include "ntru.h"
#include <algorithm>
#include <random>

Poly::Poly() : coeffs(NTRU_N, 0) {}

void Poly::mod(int modulus) {
    for (int i = 0; i < NTRU_N; ++i) {
        coeffs[i] = coeffs[i] % modulus;
        if (coeffs[i] < 0) coeffs[i] += modulus;
    }
}

NTRU::NTRU() {}

void NTRU::random_ternary(Poly& poly, int d) {
    std::vector<int> pos(NTRU_N);
    for (int i = 0; i < NTRU_N; ++i) pos[i] = i;
    // Seed RNG without Arduino entropy when building for server
    std::random_device rd;
    std::mt19937 gen(rd());
    std::shuffle(pos.begin(), pos.end(), gen);

    std::fill(poly.coeffs.begin(), poly.coeffs.end(), 0);
    for (int i = 0; i < d; ++i) poly.coeffs[pos[i]] = 1;
    for (int i = d; i < 2*d; ++i) poly.coeffs[pos[i]] = -1;
}

void NTRU::poly_mult(const Poly& a, const Poly& b, Poly& res) {
    std::fill(res.coeffs.begin(), res.coeffs.end(), 0);
    for (int i = 0; i < NTRU_N; ++i) {
        for (int j = 0; j < NTRU_N; ++j) {
            int idx = (i + j) % NTRU_N;
            res.coeffs[idx] += a.coeffs[i] * b.coeffs[j];
        }
    }
    res.mod(NTRU_Q);
}

void NTRU::poly_inv(const Poly& a, Poly& res, int mod) {
    // Placeholder: Implement extended Euclidean or Newton iteration
    std::fill(res.coeffs.begin(), res.coeffs.end(), 0);
    res.coeffs[0] = 1;
}

void NTRU::generate_keys(NTRUKeyPair& kp) {
    Poly g;
    random_ternary(kp.f, NTRU_D);
    random_ternary(g, NTRU_D);
    Poly f_inv;
    poly_inv(kp.f, f_inv, NTRU_Q);
    poly_mult(g, f_inv, kp.h);
    for (int i = 0; i < NTRU_N; ++i) kp.h.coeffs[i] = (NTRU_P * kp.h.coeffs[i]) % NTRU_Q;
}

void NTRU::encrypt(const Poly& m, const Poly& h, Poly& e) {
    Poly r;
    random_ternary(r, NTRU_D);
    poly_mult(r, h, e);
    for (int i = 0; i < NTRU_N; ++i) e.coeffs[i] = (e.coeffs[i] + m.coeffs[i]) % NTRU_Q;
}

void NTRU::decrypt(const Poly& e, const Poly& f, Poly& m) {
    Poly a;
    poly_mult(e, f, a);
    for (int i = 0; i < NTRU_N; ++i) m.coeffs[i] = a.coeffs[i] % NTRU_P;
}

void NTRU::bytes_to_poly(const std::vector<uint8_t>& bytes, Poly& poly, size_t len) {
    std::fill(poly.coeffs.begin(), poly.coeffs.end(), 0);
    for (size_t i = 0; i < len && i < NTRU_N; ++i) {
        poly.coeffs[i] = bytes[i] % NTRU_P;
    }
}

void NTRU::poly_to_bytes(const Poly& poly, std::vector<uint8_t>& bytes, size_t len) {
    bytes.resize(len);
    for (size_t i = 0; i < len && i < NTRU_N; ++i) {
        bytes[i] = static_cast<uint8_t>(poly.coeffs[i] & 0xFF);
    }
}

// Map 2 bytes per coefficient (big-endian) into poly, up to NTRU_N
void NTRU::bytes_to_poly16(const std::vector<uint8_t>& bytes, Poly& poly) {
    std::fill(poly.coeffs.begin(), poly.coeffs.end(), 0);
    size_t count = std::min(bytes.size() / 2, (size_t)NTRU_N);
    for (size_t i = 0; i < count; ++i) {
        uint16_t v = (static_cast<uint16_t>(bytes[2*i]) << 8) | bytes[2*i + 1];
        poly.coeffs[i] = static_cast<int16_t>(v % NTRU_Q);
    }
}

// Serialize each coefficient as 2 bytes (big-endian), length 2*NTRU_N
void NTRU::poly_to_bytes16(const Poly& poly, std::vector<uint8_t>& bytes) {
    bytes.resize(NTRU_N * 2);
    for (int i = 0; i < NTRU_N; ++i) {
        uint16_t v = static_cast<uint16_t>(poly.coeffs[i] & 0xFFFF);
        bytes[2*i]     = static_cast<uint8_t>((v >> 8) & 0xFF);
        bytes[2*i + 1] = static_cast<uint8_t>(v & 0xFF);
    }
}