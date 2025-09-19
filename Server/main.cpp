#include <cpprest/http_listener.h>
#include <cpprest/json.h>
#include <cpprest/uri.h>
#include <cpprest/asyncrt_utils.h>
#include <pqxx/pqxx>
#include <pqxx/except>
#include <mbedtls/md.h>
#include <mbedtls/pkcs5.h>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <regex>
#include <iostream>
#include <random>
#include "../lib/NTRU/include/ntru.h"

using namespace web;
using namespace web::http;
using namespace web::http::experimental::listener;

#define KDF_ITERATIONS 100000
#define HMAC_TAG_LEN 16

// XenoCipher structures
struct BaseKeys {
    std::vector<uint8_t> hmacKey;
    uint16_t lfsrSeed;
    std::vector<uint8_t> tinkerbellKey;
    std::vector<uint8_t> transpositionKey;
};

struct MessageKeys {
    uint16_t lfsrSeed;
    std::vector<uint8_t> tinkerbellKey;
    std::vector<uint8_t> transpositionKey;
};

struct GridSpec {
    uint8_t rows;
    uint8_t cols;
};

struct SaltMeta {
    uint16_t pos;
    uint8_t len;
};

// NTRU key pair - FIXED VERSION
class NTRUServer {
public:
    NTRUServer() : ntru() {
        ntru.generate_keys(keyPair);
    }

    std::vector<uint8_t> getPublicKey() const {
        std::vector<uint8_t> bytes(NTRU_N * 2); // 2 bytes per coefficient
        for (int i = 0; i < NTRU_N; ++i) {
            int16_t coeff = keyPair.h.coeffs[i];
            bytes[i * 2] = (coeff >> 8) & 0xFF;
            bytes[i * 2 + 1] = coeff & 0xFF;
        }
        return bytes;
    }

    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& encKey) {
        if (encKey.size() != NTRU_N * 2) {
            throw std::runtime_error("Invalid encrypted key size");
        }
        
        Poly e, m;
        
        // Convert bytes to polynomial
        for (int i = 0; i < NTRU_N; ++i) {
            e.coeffs[i] = (encKey[i * 2] << 8) | encKey[i * 2 + 1];
        }
        
        ntru.decrypt(e, keyPair.f, m);
        
        // Convert polynomial back to bytes (take first 32 bytes)
        std::vector<uint8_t> bytes(32);
        for (int i = 0; i < 32; ++i) {
            bytes[i] = m.coeffs[i] & 0xFF;
        }
        return bytes;
    }

private:
    NTRU ntru;
    NTRUKeyPair keyPair;
};

// XenoCipher functions
void deriveKeys(const std::vector<uint8_t>& masterKey, BaseKeys& out) {
    std::vector<uint8_t> salt(16, 0);
    std::vector<uint8_t> keyMaterial(48);
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
    mbedtls_pkcs5_pbkdf2_hmac(&ctx, masterKey.data(), masterKey.size(), salt.data(), salt.size(), KDF_ITERATIONS, 48, keyMaterial.data());
    mbedtls_md_free(&ctx);

    out.hmacKey.assign(keyMaterial.begin(), keyMaterial.begin() + 32);
    out.lfsrSeed = (keyMaterial[32] << 8) | keyMaterial[33];
    out.tinkerbellKey.assign(keyMaterial.begin() + 34, keyMaterial.begin() + 42);
    out.transpositionKey.assign(keyMaterial.begin() + 40, keyMaterial.begin() + 48);
}

void deriveMessageKeys(const BaseKeys& baseKeys, uint32_t nonce, MessageKeys& out) {
    std::vector<uint8_t> seed(4);
    seed[0] = (nonce >> 24) & 0xFF;
    seed[1] = (nonce >> 16) & 0xFF;
    seed[2] = (nonce >> 8) & 0xFF;
    seed[3] = nonce & 0xFF;

    std::vector<uint8_t> keyMaterial(32);
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
    mbedtls_md_hmac_starts(&ctx, baseKeys.hmacKey.data(), baseKeys.hmacKey.size());
    mbedtls_md_hmac_update(&ctx, seed.data(), seed.size());
    mbedtls_md_hmac_finish(&ctx, keyMaterial.data());
    mbedtls_md_free(&ctx);

    out.lfsrSeed = (keyMaterial[0] << 8) | keyMaterial[1];
    out.tinkerbellKey.assign(keyMaterial.begin() + 2, keyMaterial.begin() + 10);
    out.transpositionKey.assign(keyMaterial.begin() + 10, keyMaterial.begin() + 18);
}

void chaoticLFSR32(uint16_t seed, const std::vector<uint8_t>& tinkerbellKey, uint32_t poly, std::vector<uint8_t>& data) {
    uint32_t state = seed;
    for (size_t i = 0; i < data.size(); i++) {
        uint32_t bit = 0;
        for (int j = 0; j < 32; j++) {
            bit ^= (state >> j) & 1;
        }
        state = (state << 1) | bit;
        data[i] ^= (state & 0xFF);
    }
}

void tinkerbell(const std::vector<uint8_t>& key, std::vector<uint8_t>& data) {
    for (size_t i = 0; i < data.size(); i++) {
        data[i] ^= key[i % key.size()];
    }
}

void applyTransposition(std::vector<uint8_t>& data, const GridSpec& grid, const std::vector<uint8_t>& key, const std::string& mode) {
    std::vector<uint8_t> temp = data;
    for (size_t i = 0; i < data.size(); i++) {
        size_t idx = (mode == "forward") ? (i + key[i % key.size()]) % data.size() : (i - key[i % key.size()] + data.size()) % data.size();
        data[i] = temp[idx];
    }
}

std::vector<uint8_t> removeSalt(const std::vector<uint8_t>& salted, size_t saltedLen, const SaltMeta& meta) {
    if (meta.len == 0 || meta.pos > saltedLen) return salted;
    std::vector<uint8_t> out(saltedLen - meta.len);
    std::copy(salted.begin(), salted.begin() + meta.pos, out.begin());
    std::copy(salted.begin() + meta.pos + meta.len, salted.end(), out.begin() + meta.pos);
    return out;
}

std::string pipelineDecryptPacket(const BaseKeys& baseKeys, const std::vector<uint8_t>& packet, size_t packetLen) {
    if (packetLen < 8 + HMAC_TAG_LEN) return "";

    std::vector<uint8_t> header(packet.begin(), packet.begin() + 8);
    uint8_t version = header[0];
    bool hasNonce = (version & 0x80) != 0;
    size_t nonceLen = hasNonce ? 4 : 0;
    if (packetLen < 8 + nonceLen + HMAC_TAG_LEN) return "";

    uint8_t saltLen = header[1];
    uint16_t saltPos = (header[2] | (header[3] << 8));
    uint16_t payloadLen = (header[4] | (header[5] << 8));
    uint8_t rows = header[6];
    uint8_t cols = header[7];
    GridSpec grid = {rows, cols};
    SaltMeta saltMeta = {saltPos, saltLen};

    std::vector<uint8_t> noncePtr = hasNonce ? std::vector<uint8_t>(packet.begin() + 8, packet.begin() + 12) : std::vector<uint8_t>();
    uint32_t nonce = hasNonce ? ((noncePtr[0] << 24) | (noncePtr[1] << 16) | (noncePtr[2] << 8) | noncePtr[3]) : 0;
    std::vector<uint8_t> ct(packet.begin() + 8 + nonceLen, packet.end() - HMAC_TAG_LEN);
    std::vector<uint8_t> tag(packet.end() - HMAC_TAG_LEN, packet.end());

    std::vector<uint8_t> tagCheck(32);
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
    mbedtls_md_hmac_starts(&ctx, baseKeys.hmacKey.data(), baseKeys.hmacKey.size());
    mbedtls_md_hmac_update(&ctx, packet.data(), packetLen - HMAC_TAG_LEN);
    mbedtls_md_hmac_finish(&ctx, tagCheck.data());
    mbedtls_md_free(&ctx);
    tagCheck.resize(HMAC_TAG_LEN);

    if (tag != tagCheck) {
        std::cerr << "MAC verification failed!" << std::endl;
        return "";
    }

    MessageKeys messageKeys;
    deriveMessageKeys(baseKeys, nonce, messageKeys);

    std::vector<uint8_t> buf = ct;
    applyTransposition(buf, grid, messageKeys.transpositionKey, "inverse");
    tinkerbell(messageKeys.tinkerbellKey, buf);
    chaoticLFSR32(messageKeys.lfsrSeed, messageKeys.tinkerbellKey, 0x0029, buf);

    std::vector<uint8_t> recovered = removeSalt(buf, buf.size(), saltMeta);
    return std::string(recovered.begin(), recovered.begin() + payloadLen);
}

// Hex string conversion
std::vector<uint8_t> hexToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = (uint8_t)std::stoul(byteString, nullptr, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

std::string bytesToHex(const std::vector<uint8_t>& bytes) {
    std::stringstream ss;
    ss << std::hex << std::uppercase << std::setfill('0');
    for (uint8_t b : bytes) {
        ss << std::setw(2) << (int)b;
    }
    return ss.str();
}

int main() {
    // PostgreSQL connection
    pqxx::connection conn("dbname=XenoCipherTesting user=postgres password=vivek host=localhost port=5432");
    if (!conn.is_open()) {
        std::cerr << "Failed to connect to PostgreSQL" << std::endl;
        return 1;
    }

    // Initialize NTRU
    NTRUServer ntru;
    std::vector<uint8_t> masterKey;

    // Test the public key generation
    auto pubKey = ntru.getPublicKey();
    std::cout << "Public key generated successfully!" << std::endl;
    std::cout << "Public key size: " << pubKey.size() << " bytes" << std::endl;
    
    // Check if key looks reasonable (should not be all zeros)
    bool allZeros = true;
    for (const auto& byte : pubKey) {
        if (byte != 0) {
            allZeros = false;
            break;
        }
    }
    
    if (allZeros) {
        std::cerr << "ERROR: Public key is all zeros! NTRU key generation failed!" << std::endl;
        return 1;
    }
    
    std::cout << "First 16 bytes of public key: ";
    for (int i = 0; i < 16 && i < pubKey.size(); ++i) {
        printf("%02X ", pubKey[i]);
    }
    std::cout << std::endl;

    // HTTP server
    http_listener listener(web::uri(U("http://+:8081")));

    // GET /public-key
    listener.support(methods::GET, [&ntru](http_request req) {
        if (req.relative_uri().to_string() == U("/public-key")) {
            auto pubKey = ntru.getPublicKey();
            std::string pubHex = bytesToHex(pubKey);
            
            // Debug output
            std::cout << "=== Sending Public Key ===" << std::endl;
            std::cout << "Key length: " << pubKey.size() << " bytes" << std::endl;
            std::cout << "First 16 bytes: ";
            for (int i = 0; i < 16 && i < pubKey.size(); ++i) {
                printf("%02X ", pubKey[i]);
            }
            std::cout << std::endl;
            
            json::value response;
            response[U("publicKey")] = json::value::string(U("PUBHEX:") + utility::conversions::to_string_t(pubHex));
            req.reply(status_codes::OK, response);
        } else {
            req.reply(status_codes::NotFound);
        }
    });

    // POST /master-key
    listener.support(methods::POST, [&ntru, &conn, &masterKey](http_request req) {
        if (req.relative_uri().to_string() == U("/master-key")) {
            std::cout << "Received POST /master-key request" << std::endl;
            req.extract_json().then([&](json::value body) {
                try {
                    std::string encKey = utility::conversions::to_utf8string(body[U("data")].as_string());
                    std::cout << "Received encrypted key: " << encKey.substr(0, 50) << "..." << std::endl;
                    
                    if (encKey.substr(0, 7) != "ENCKEY:") {
                        std::cerr << "Invalid master key format" << std::endl;
                        req.reply(status_codes::BadRequest, json::value::object({{U("error"), json::value::string(U("Invalid ENCKEY format"))}}));
                        return;
                    }
                    
                    std::string encKeyHex = encKey.substr(7);
                    auto encKeyBytes = hexToBytes(encKeyHex);
                    std::cout << "Decrypting " << encKeyBytes.size() << " bytes..." << std::endl;
                    
                    masterKey = ntru.decrypt(encKeyBytes);
                    std::string masterKeyHex = bytesToHex(masterKey);
                    
                    std::cout << "Master key decrypted: " << masterKeyHex << std::endl;
                    
                    pqxx::work txn(conn);
                    txn.exec_prepared("insert_master_key", masterKeyHex);
                    txn.commit();
                    
                    req.reply(status_codes::OK, json::value::object({{U("status"), json::value::string(U("OK:Encrypted key received"))}}));
                } catch (const std::exception& e) {
                    std::cerr << "Error in /master-key: " << e.what() << std::endl;
                    req.reply(status_codes::InternalError, json::value::object({{U("error"), json::value::string(U("Server error"))}}));
                }
            }).wait();
        }
    });

    // POST /health-data
    listener.support(methods::POST, [&conn, &masterKey](http_request req) {
        if (req.relative_uri().to_string() == U("/health-data")) {
            if (masterKey.empty()) {
                req.reply(status_codes::BadRequest, json::value::object({{U("error"), json::value::string(U("No master key"))}}));
                return;
            }
            
            req.extract_json().then([&](json::value body) {
                try {
                    std::string encData = utility::conversions::to_utf8string(body[U("data")].as_string());
                    
                    if (encData.substr(0, 9) != "ENC_DATA:") {
                        req.reply(status_codes::BadRequest, json::value::object({{U("error"), json::value::string(U("Invalid ENC_DATA format"))}}));
                        return;
                    }
                    
                    std::string packetHex = encData.substr(9);
                    auto packet = hexToBytes(packetHex);
                    
                    BaseKeys baseKeys;
                    deriveKeys(masterKey, baseKeys);
                    std::string decrypted = pipelineDecryptPacket(baseKeys, packet, packet.size());
                    
                    if (decrypted.empty()) {
                        req.reply(status_codes::BadRequest, json::value::object({{U("error"), json::value::string(U("Decryption failed"))}}));
                        return;
                    }

                    std::regex regex("HR-(\\d+) SPO2-(\\d+) STEPS-(\\d+)");
                    std::smatch match;
                    if (!std::regex_match(decrypted, match, regex)) {
                        req.reply(status_codes::BadRequest, json::value::object({{U("error"), json::value::string(U("Invalid data format"))}}));
                        return;
                    }
                    
                    int heart_rate = std::stoi(match[1]);
                    int spo2 = std::stoi(match[2]);
                    int steps = std::stoi(match[3]);

                    pqxx::work txn(conn);
                    txn.exec_prepared("insert_health_data", heart_rate, spo2, steps);
                    txn.commit();
                    
                    req.reply(status_codes::OK, json::value::object({{U("status"), json::value::string(U("ENC_OK:Stored"))}}));
                } catch (const std::exception& e) {
                    std::cerr << "Error in /health-data: " << e.what() << std::endl;
                    req.reply(status_codes::InternalError, json::value::object({{U("error"), json::value::string(U("Server error"))}}));
                }
            }).wait();
        }
    });

    try {
        // Prepare SQL statements
        pqxx::work prep(conn);
        prep.exec("PREPARE insert_master_key (text) AS INSERT INTO master_keys (master_key) VALUES ($1)");
        prep.exec("PREPARE insert_health_data (smallint, smallint, integer) AS INSERT INTO health_data (heart_rate, spo2, steps) VALUES ($1, $2, $3)");
        prep.commit();

        listener.open().wait();
        std::cout << "Server running on http://localhost:8081" << std::endl;
        std::cout << "Press Enter to stop the server..." << std::endl;
        std::string line;
        std::getline(std::cin, line);
        listener.close().wait();
    } catch (const std::exception& e) {
        std::cerr << "Server Error: " << e.what() << std::endl;
    }

    return 0;
}