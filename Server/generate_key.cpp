#include <cpprest/http_client.h>
#include <cpprest/json.h>
#include <iostream>
#include <vector>
#include "../lib/NTRU/include/ntru.h"

std::vector<uint8_t> hexToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        bytes.push_back((uint8_t)std::stoul(byteString, nullptr, 16));
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
    web::http::client::http_client client(U("http://localhost:8081"));
    client.request(web::http::methods::GET, U("/public-key")).then([](web::http::http_response response) {
        return response.extract_json();
    }).then([](web::json::value body) {
        std::string pubKey = utility::conversions::to_utf8string(body[U("publicKey")].as_string());
        if (pubKey.substr(0, 7) != "PUBHEX:") {
            std::cerr << "Invalid public key format" << std::endl;
            return;
        }
        pubKey = pubKey.substr(7);
        NTRU ntru;
        std::vector<uint8_t> masterKey(32, 0x01); // Dummy 32-byte key
        std::vector<uint8_t> encKey;
        ntru.encrypt(masterKey, hexToBytes(pubKey), encKey);
        std::cout << "encKey: ENCKEY:" << bytesToHex(encKey) << std::endl;
    }).wait();
    return 0;
}