#ifndef NTRU_H
#define NTRU_H

#include <cstdint>
#include <vector>
#if defined(ARDUINO) || defined(ESP_PLATFORM)
#include "../../Entropy/include/entropy.h"
#endif

#define NTRU_N 251
#define NTRU_P 3
#define NTRU_Q 128
#define NTRU_D 71

class Poly {
public:
    std::vector<int16_t> coeffs;
    Poly();
    void mod(int modulus);
};

class NTRUKeyPair {
public:
    Poly h;  // Public key
    Poly f;  // Private key
};

class NTRU {
public:
    NTRU();
    void generate_keys(NTRUKeyPair& kp);
    void encrypt(const Poly& m, const Poly& h, Poly& e);
    void decrypt(const Poly& e, const Poly& f, Poly& m);
    static void bytes_to_poly(const std::vector<uint8_t>& bytes, Poly& poly, size_t len);
    static void poly_to_bytes(const Poly& poly, std::vector<uint8_t>& bytes, size_t len);
    // 16-bit per coefficient (big-endian) serialization helpers
    static void bytes_to_poly16(const std::vector<uint8_t>& bytes, Poly& poly);
    static void poly_to_bytes16(const Poly& poly, std::vector<uint8_t>& bytes);
private:
    void poly_mult(const Poly& a, const Poly& b, Poly& res);
    void poly_inv(const Poly& a, Poly& res, int mod);
    void random_ternary(Poly& poly, int d);
};

#endif