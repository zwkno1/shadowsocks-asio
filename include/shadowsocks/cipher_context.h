#pragma once

#include <cryptopp/cryptlib.h>
#include <cryptopp/secblock.h>
#include <cryptopp/chacha.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>
#include <cryptopp/hex.h>
#include <cryptopp/modes.h>
#include <cryptopp/aes.h>
#include <cryptopp/blowfish.h>
#include <cryptopp/camellia.h>

#include <shadowsocks/cipher_context.h>

namespace shadowsocks
{

enum cipher_type : uint8_t
{
    STREAM,
    AEAD
};

struct cipher_info 
{
    // internal implementation name in Botan
    std::string name_;
    size_t key_length_;
    size_t iv_length_;
    cipher_type type_;
    size_t salt_length_; // only for AEAD
    size_t tag_length_; // only for AEAD
};

const std::unordered_map<std::string, cipher_info> cipherInfoMap = 
{
    {"aes-128-cfb", {"AES-128/CFB", 16, 16, STREAM}},
    {"aes-192-cfb", {"AES-192/CFB", 24, 16, STREAM}},
    {"aes-256-cfb", {"AES-256/CFB", 32, 16, STREAM}},
    {"aes-128-ctr", {"AES-128/CTR-BE", 16, 16, STREAM}},
    {"aes-192-ctr", {"AES-192/CTR-BE", 24, 16, STREAM}},
    {"aes-256-ctr", {"AES-256/CTR-BE", 32, 16, STREAM}},
    {"bf-cfb", {"Blowfish/CFB", 16, 8, STREAM}},
    {"camellia-128-cfb", {"Camellia-128/CFB", 16, 16, STREAM}},
    {"camellia-192-cfb", {"Camellia-192/CFB", 24, 16, STREAM}},
    {"camellia-256-cfb", {"Camellia-256/CFB", 32, 16, STREAM}},
    {"cast5-cfb", {"CAST-128/CFB", 16, 8, STREAM}},
    {"chacha20", {"ChaCha", 32, 8, STREAM}},
    {"chacha20-ietf", {"ChaCha", 32, 12, STREAM}},
    {"des-cfb", {"DES/CFB", 8, 8, STREAM}},
    {"idea-cfb", {"IDEA/CFB", 16, 8, STREAM}},
    // RC2 is not supported by botan-2
    {"rc2-cfb", {"RC2/CFB", 16, 8, STREAM}},
    {"rc4-md5", {"RC4-MD5", 16, 16, STREAM}},
    {"salsa20", {"Salsa20", 32, 8, STREAM}},
    {"seed-cfb", {"SEED/CFB", 16, 16, STREAM}},
    {"serpent-256-cfb", {"Serpent/CFB", 32, 16, STREAM}},
    {"chacha20-ietf-poly1305", {"ChaCha20Poly1305", 32, 12, AEAD, 32, 16}},
    {"aes-128-gcm", {"AES-128/GCM", 16, 12, AEAD, 16, 16}},
    {"aes-192-gcm", {"AES-192/GCM", 24, 12, AEAD, 24, 16}},
    {"aes-256-gcm", {"AES-256/GCM", 32, 12, AEAD, 32, 16}}
};

struct chacha
{
    CryptoPP::ChaCha::Encryption enc_;
    CryptoPP::ChaCha::Decryption dec_;
    
    void encryt(uint8_t * out, uint8_t * in, size_t size)
    {
        enc_.ProcessData(out, in, size);
    }
    
    void decryt(uint8_t * out, uint8_t * in, size_t size)
    {
        enc_.ProcessData(out, in, size);
    }
};

struct aes_cfb
{
    CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption enc_;
    CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption dec_;
    
    void encryt(uint8_t * out, uint8_t * in, size_t size)
    {
        enc_.ProcessData(out, in, size);
    }
    
    void decryt(uint8_t * out, uint8_t * in, size_t size)
    {
    }
};

struct aes_ctr
{
    CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption enc_;
    CryptoPP::CTR_Mode<CryptoPP::AES>::Decryption dec_;
};

struct bf_cfb
{
    CryptoPP::CFB_Mode<CryptoPP::Blowfish>::Encryption enc_;
    CryptoPP::CFB_Mode<CryptoPP::Blowfish>::Decryption dec_;
};

struct camellia_cfb
{
    CryptoPP::CFB_Mode<CryptoPP::Camellia>::Encryption enc_;
    CryptoPP::CFB_Mode<CryptoPP::Camellia>::Decryption dec_;
};


class cipher_context
{
public:
    cipher_context(const std::string & algo_spec, const std::vector<uint8_t> & key, size_t iv_length)
    {
    }

    //std::array<engine, 2> engine_;
};

}
