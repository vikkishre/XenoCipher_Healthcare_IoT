#include <crow.h>
#include <pqxx/pqxx>
#include <mbedtls/md.h>
#include <mbedtls/pkcs5.h>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <regex>
#include "../lib/NTRU/include/ntru.h"
#include "../lib/common/common.h"
#include "../lib/CryptoKDF/include/crypto_kdf.h"
#include "../lib/HMAC/include/hmac.h"
#include "../lib/LFSR/include/lfsr.h"
#include "../lib/Tinkerbell/include/tinkerbell.h"
#include "../lib/Transposition/include/transposition.h"

using namespace std;

// KDF_ITERATIONS is defined in crypto_kdf.h
#define HMAC_TAG_LEN 16

// Use lib structures instead of custom ones
// BaseKeys and MessageKeys are defined in crypto_kdf.h

// GridSpec is defined in transposition.h

struct SaltMeta {
    uint16_t pos;
    uint8_t len;
};

// NTRU key pair
class NTRUServer {
public:
    NTRUServer() : ntru() {
        ntru.generate_keys(keyPair);
    }

    std::vector<uint8_t> getPublicKey() const {
        std::vector<uint8_t> bytes;
        NTRU::poly_to_bytes(keyPair.h, bytes, NTRU_N * sizeof(int16_t));
        return bytes;
    }

    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& encKey) {
        Poly e, m;
        NTRU::bytes_to_poly(encKey, e, encKey.size());
        ntru.decrypt(e, keyPair.f, m);
        std::vector<uint8_t> bytes;
        NTRU::poly_to_bytes(m, bytes, 32); // Assuming 32-byte master key
        return bytes;
    }

private:
    NTRU ntru;
    NTRUKeyPair keyPair;
};

// Use lib deriveKeys function instead of custom implementation

// Use lib deriveMessageKeys function instead of custom implementation

// Use lib ChaoticLFSR32 class instead of custom implementation

// Use lib Tinkerbell class instead of custom implementation

// Use lib applyTransposition function instead of custom implementation

std::vector<uint8_t> removeSalt(const std::vector<uint8_t>& salted, size_t saltedLen, const SaltMeta& meta) {
    if (meta.len == 0 || meta.pos > saltedLen) return salted;
    std::vector<uint8_t> out(saltedLen - meta.len);
    std::copy(salted.begin(), salted.begin() + meta.pos, out.begin());
    std::copy(salted.begin() + meta.pos + meta.len, salted.end(), out.begin() + meta.pos);
    return out;
}

std::string pipelineDecryptPacket(const DerivedKeys& baseKeys, const std::vector<uint8_t>& packet, size_t packetLen) {
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

    std::vector<uint8_t> noncePtr = hasNonce ? std::vector<uint8_t>(packet.begin() + 8, packet.begin() + 8 + nonceLen) : std::vector<uint8_t>();
    uint32_t nonce = hasNonce ? ((noncePtr[0] << 24) | (noncePtr[1] << 16) | (noncePtr[2] << 8) | noncePtr[3]) : 0;
    
    // Get encrypted data and HMAC tag
    std::vector<uint8_t> ct(packet.begin() + 8 + nonceLen, packet.end() - HMAC_TAG_LEN);
    std::vector<uint8_t> tag(packet.end() - HMAC_TAG_LEN, packet.end());

    // Debug: print header fields
    {
        std::cout << "[Server] Header: ver=0x" << std::hex << std::uppercase << (int)version
                  << " saltLen=" << std::dec << (int)saltLen
                  << " saltPos=" << saltPos
                  << " payloadLen=" << payloadLen
                  << " rows=" << (int)rows
                  << " cols=" << (int)cols
                  << " nonce=0x" << std::hex << std::uppercase << nonce << std::dec
                  << std::endl;
    }

    MessageKeys hmacKeys;
    if (!deriveMessageKeys(baseKeys, nonce, hmacKeys)) {
        std::cerr << "Failed to derive message-specific HMAC key!" << std::endl;
        return "";
    }

    // Verify HMAC using base HMAC key
    const size_t headerLen = 8;
    const size_t inputLen = headerLen + nonceLen + ct.size();
    uint8_t tagCheck[HMAC_TAG_LEN];
    if (!hmac_sha256_trunc(baseKeys.hmacKey, 32,
                           packet.data(), inputLen,
                           tagCheck, HMAC_TAG_LEN)) {
        std::cerr << "HMAC computation failed!" << std::endl;
        return "";
    }

    // Debug: print HMAC key prefix and tags
    {
        std::ostringstream hk, tp, tc, hi;
        hk << std::hex << std::uppercase << std::setfill('0');
        for (int i = 0; i < 16; ++i) hk << std::setw(2) << (int)baseKeys.hmacKey[i];
        tp << std::hex << std::uppercase << std::setfill('0');
        tc << std::hex << std::uppercase << std::setfill('0');
        hi << std::hex << std::uppercase << std::setfill('0');
        for (int i = 0; i < (int)HMAC_TAG_LEN; ++i) {
            tp << std::setw(2) << (int)tag[i];
            tc << std::setw(2) << (int)tagCheck[i];
        }
        // Print first 16 bytes of HMAC input for debugging
        for (int i = 0; i < 16 && i < (int)inputLen; ++i) {
            hi << std::setw(2) << (int)packet[i];
        }
        std::cout << "[Server] Base HMAC key[0..15]=" << hk.str()
                  << " input[0..15]=" << hi.str()
                  << " inputLen=" << inputLen
                  << " tag(prov)=" << tp.str()
                  << " tag(calc)=" << tc.str() << std::endl;
    }

    // Constant-time tag compare
    uint8_t diff = 0;
    for (size_t i = 0; i < HMAC_TAG_LEN; ++i) diff |= (uint8_t)(tag[i] ^ tagCheck[i]);
    bool macValid = (diff == 0);

    if (!macValid) {
        std::cerr << "MAC verification failed!" << std::endl;
        return "";
    }

    MessageKeys messageKeys;
    deriveMessageKeys(baseKeys, nonce, messageKeys);

    std::vector<uint8_t> buf = ct;
    
    // First decrypt the data with all three algorithms
    applyTransposition(buf.data(), grid, messageKeys.transpositionKey, PermuteMode::Inverse);
    
    Tinkerbell tk(messageKeys.tinkerbellKey);
    tk.xorBitwise(buf.data(), buf.size());
    
    ChaoticLFSR32 lfsr((uint32_t)messageKeys.lfsrSeed, messageKeys.tinkerbellKey, 0x0029u);
    lfsr.xorBuffer(buf.data(), buf.size());

    // After decryption, remove the salt
    std::vector<uint8_t> unsalted = removeSalt(buf, buf.size(), saltMeta);
    return std::string(unsalted.begin(), unsalted.begin() + payloadLen);
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
    pqxx::connection conn("dbname=XenoCipherTesting user=postgres password=challa host=localhost port=5433");
    if (!conn.is_open()) {
        std::cerr << "Failed to connect to PostgreSQL" << std::endl;
        return 1;
    }

    // Initialize NTRU
    NTRUServer ntru;
    std::vector<uint8_t> masterKey;

    // Create Crow app
    crow::SimpleApp app;

    // CORS middleware
    CROW_ROUTE(app, "/")
    .methods("OPTIONS"_method)
    ([]() {
        crow::response res(200);
        res.add_header("Access-Control-Allow-Origin", "*");
        res.add_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        res.add_header("Access-Control-Allow-Headers", "Content-Type");
        return res;
    });

    // GET /public-key
    CROW_ROUTE(app, "/public-key")
    .methods("GET"_method)
    ([&ntru]() {
        try {
            auto pubKey = ntru.getPublicKey();
            std::string pubHex = bytesToHex(pubKey);
            
            crow::json::wvalue response;
            response["publicKey"] = "PUBHEX:" + pubHex;
            
            crow::response res(200, response);
            res.add_header("Access-Control-Allow-Origin", "*");
            return res;
        } catch (const std::exception& e) {
            std::cerr << "Error in /public-key: " << e.what() << std::endl;
            crow::response res(500, crow::json::wvalue{{"error", "Server error"}});
            res.add_header("Access-Control-Allow-Origin", "*");
            return res;
        }
    });

    // POST /master-key
    CROW_ROUTE(app, "/master-key")
    .methods("POST"_method, "OPTIONS"_method)
    ([&ntru, &conn, &masterKey](const crow::request& req) {
        if (req.method == "OPTIONS"_method) {
            crow::response res(200);
            res.add_header("Access-Control-Allow-Origin", "*");
            res.add_header("Access-Control-Allow-Methods", "POST, OPTIONS");
            res.add_header("Access-Control-Allow-Headers", "Content-Type");
            return res;
        }

        try {
            std::cout << "Received POST /master-key request" << std::endl;
            
            auto body = crow::json::load(req.body);
            if (!body || !body.has("encKey")) {
                crow::response res(400, crow::json::wvalue{{"error", "Missing encKey field"}});
                res.add_header("Access-Control-Allow-Origin", "*");
                return res;
            }

            std::string encKey = body["encKey"].s();
            
            if (encKey.substr(0, 7) != "ENCKEY:") {
                std::cerr << "Invalid master key format" << std::endl;
                crow::response res(400, crow::json::wvalue{{"error", "Invalid ENCKEY format"}});
                res.add_header("Access-Control-Allow-Origin", "*");
                return res;
            }
            
            std::string encKeyHex = encKey.substr(7);
            auto encKeyBytes = hexToBytes(encKeyHex);
            
            masterKey = ntru.decrypt(encKeyBytes);
            // No additional reduction needed - use the decrypted key directly
            std::string masterKeyHex = bytesToHex(masterKey);

            {
                std::ostringstream mk;
                mk << std::hex << std::uppercase << std::setfill('0');
                for (int i = 0; i < 16; ++i) mk << std::setw(2) << (int)masterKey[i];
                std::cout << "[Server] Decrypted master key[0..15]: " << mk.str() << std::endl;
            }

            // Derive and log HMAC key prefix for debugging
            {
                DerivedKeys dbg;
                deriveKeys(masterKey.data(), masterKey.size(), dbg);
                std::ostringstream hk;
                hk << std::hex << std::uppercase << std::setfill('0');
                for (int i = 0; i < 16; ++i) hk << std::setw(2) << (int)dbg.hmacKey[i];
                std::cout << "[Server] HMAC key[0..15] after /master-key: " << hk.str() << std::endl;
            }
            
            std::cout << "Master key decrypted and stored" << std::endl;
            
            pqxx::work txn(conn);
            txn.exec_prepared("insert_master_key", masterKeyHex);
            txn.commit();
            
            crow::json::wvalue response;
            response["status"] = "OK:Encrypted key received";
            
            crow::response res(200, response);
            res.add_header("Access-Control-Allow-Origin", "*");
            return res;
            
        } catch (const std::exception& e) {
            std::cerr << "Error in /master-key: " << e.what() << std::endl;
            crow::response res(500, crow::json::wvalue{{"error", "Server error"}});
            res.add_header("Access-Control-Allow-Origin", "*");
            return res;
        }
    });

    // POST /health-data
    CROW_ROUTE(app, "/health-data")
    .methods("POST"_method, "OPTIONS"_method)
    ([&conn, &masterKey](const crow::request& req) {
        if (req.method == "OPTIONS"_method) {
            crow::response res(200);
            res.add_header("Access-Control-Allow-Origin", "*");
            res.add_header("Access-Control-Allow-Methods", "POST, OPTIONS");
            res.add_header("Access-Control-Allow-Headers", "Content-Type");
            return res;
        }

        if (masterKey.empty()) {
            crow::response res(400, crow::json::wvalue{{"error", "No master key available"}});
            res.add_header("Access-Control-Allow-Origin", "*");
            return res;
        }
        
        try {
            auto body = crow::json::load(req.body);
            if (!body || !body.has("encData")) {
                crow::response res(400, crow::json::wvalue{{"error", "Missing encData field"}});
                res.add_header("Access-Control-Allow-Origin", "*");
                return res;
            }

            std::string encData = body["encData"].s();
            
            if (encData.substr(0, 9) != "ENC_DATA:") {
                crow::response res(400, crow::json::wvalue{{"error", "Invalid ENC_DATA format"}});
                res.add_header("Access-Control-Allow-Origin", "*");
                return res;
            }
            
            std::string packetHex = encData.substr(9);
            auto packet = hexToBytes(packetHex);
            
            DerivedKeys baseKeys;
            deriveKeys(masterKey.data(), masterKey.size(), baseKeys);
            {
                std::ostringstream hk;
                hk << std::hex << std::uppercase << std::setfill('0');
                for (int i = 0; i < 16; ++i) hk << std::setw(2) << (int)baseKeys.hmacKey[i];
                std::cout << "[Server] HMAC key[0..15] at /health-data: " << hk.str() << std::endl;
            }
            
            std::string decrypted = pipelineDecryptPacket(baseKeys, packet, packet.size());
            
            if (decrypted.empty()) {
                std::cerr << "Decryption failed" << std::endl;
                crow::response res(400, crow::json::wvalue{{"error", "Decryption failed"}});
                res.add_header("Access-Control-Allow-Origin", "*");
                return res;
            }

            // Parse health data
            std::regex regex_pattern("HR-(\\d+) SPO2-(\\d+) STEPS-(\\d+)");
            std::smatch match;
            if (!std::regex_match(decrypted, match, regex_pattern)) {
                std::cerr << "Invalid data format: " << decrypted << std::endl;
                crow::response res(400, crow::json::wvalue{{"error", "Invalid data format"}});
                res.add_header("Access-Control-Allow-Origin", "*");
                return res;
            }
            
            int heart_rate = std::stoi(match[1]);
            int spo2 = std::stoi(match[2]);
            int steps = std::stoi(match[3]);

            std::cout << "Health data received - HR: " << heart_rate << ", SPO2: " << spo2 << ", Steps: " << steps << std::endl;

            pqxx::work txn(conn);
            txn.exec_prepared("insert_health_data", heart_rate, spo2, steps);
            txn.commit();
            
            crow::json::wvalue response;
            response["status"] = "ENC_OK:Stored";
            
            crow::response res(200, response);
            res.add_header("Access-Control-Allow-Origin", "*");
            return res;
            
        } catch (const std::exception& e) {
            std::cerr << "Error in /health-data: " << e.what() << std::endl;
            crow::response res(500, crow::json::wvalue{{"error", "Server error"}});
            res.add_header("Access-Control-Allow-Origin", "*");
            return res;
        }
    });

    try {
        // Prepare SQL statements
        pqxx::work prep(conn);
        prep.exec("PREPARE insert_master_key (text) AS INSERT INTO master_keys (master_key) VALUES ($1)");
        prep.exec("PREPARE insert_health_data (smallint, smallint, integer) AS INSERT INTO health_data (heart_rate, spo2, steps) VALUES ($1, $2, $3)");
        prep.commit();

        std::cout << "Starting XenoCipher Server on 0.0.0.0:8081..." << std::endl;
        std::cout << "Available endpoints:" << std::endl;
        std::cout << "  GET  /public-key" << std::endl;
        std::cout << "  POST /master-key" << std::endl;
        std::cout << "  POST /health-data" << std::endl;
        std::cout << "Press Ctrl+C to stop" << std::endl;

        app.bindaddr("0.0.0.0").port(8081).multithreaded().run();

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    return 0;
}
