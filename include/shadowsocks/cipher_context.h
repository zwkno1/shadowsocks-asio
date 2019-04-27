#pragma once

#include <variant>
#include <unordered_map>
#include <type_traits>

#include <cryptopp/cryptlib.h>
#include <cryptopp/secblock.h>
#include <cryptopp/chacha.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>
#include <cryptopp/hex.h>
#include <cryptopp/aes.h>
#include <cryptopp/blowfish.h>
#include <cryptopp/camellia.h>
#include <cryptopp/chacha.h>
#include <cryptopp/des.h>
#include <cryptopp/idea.h>
#include <cryptopp/rc2.h>
#include <cryptopp/salsa.h>
#include <cryptopp/seed.h>
#include <cryptopp/serpent.h>
#include <cryptopp/modes.h>
#include <cryptopp/chachapoly.h>

#include <shadowsocks/cipher_context.h>
#include <boost/asio.hpp>

namespace shadowsocks
{

enum cipher_type : uint8_t
{
    STREAM,
    AEAD
};

enum cipher_metod
{
    AES_CFB,
    AES_CTR_BE,
    BLOWFISH_CFB,
    CAMELLIA_CFB,
    CAST_CFB,
    CHACHA20,
    //CHACHA20_IETF,
    DES_CFB,
    IDEA_CFB,
    RC2_CFB,
    RC4_MD5,
    SALSA20,
    SEED_CFB,
    SERPENT_CFB,
    CHACHA20_POLY1305,
    AES_GCM,
};


struct cipher_info 
{
    cipher_metod method_;
    size_t key_length_;
    size_t iv_length_;
    cipher_type type_;
    size_t salt_length_; // only for AEAD
    size_t tag_length_; // only for AEAD
};

const std::unordered_map<std::string, cipher_info> cipherInfoMap = 
{
    {"aes-128-cfb", {AES_CFB, 16, 16, STREAM}},
    {"aes-192-cfb", {AES_CFB, 24, 16, STREAM}},
    {"aes-256-cfb", {AES_CFB, 32, 16, STREAM}},
    {"aes-128-ctr", {AES_CTR_BE, 16, 16, STREAM}},
    {"aes-192-ctr", {AES_CTR_BE, 24, 16, STREAM}},
    {"aes-256-ctr", {AES_CTR_BE, 32, 16, STREAM}},
    {"bf-cfb", {BLOWFISH_CFB, 16, 8, STREAM}},
    {"camellia-128-cfb", {CAMELLIA_CFB, 16, 16, STREAM}},
    {"camellia-192-cfb", {CAMELLIA_CFB, 24, 16, STREAM}},
    {"camellia-256-cfb", {CAMELLIA_CFB, 32, 16, STREAM}},
    {"cast5-cfb", {CAST_CFB, 16, 8, STREAM}},
    {"chacha20", {CHACHA20, 32, 8, STREAM}},
    {"chacha20-ietf", {CHACHA20, 32, 12, STREAM}},
    {"des-cfb", {DES_CFB, 8, 8, STREAM}},
    {"idea-cfb", {IDEA_CFB, 16, 8, STREAM}},
    {"rc2-cfb", {RC2_CFB, 16, 8, STREAM}},
    {"rc4-md5", {RC4_MD5, 16, 16, STREAM}},
    {"salsa20", {SALSA20, 32, 8, STREAM}},
    {"seed-cfb", {SEED_CFB, 16, 16, STREAM}},
    {"serpent-256-cfb", {SERPENT_CFB, 32, 16, STREAM}},
    {"chacha20-ietf-poly1305", {CHACHA20_POLY1305, 32, 12, AEAD, 32, 16}},
    {"aes-128-gcm", {AES_GCM, 16, 12, AEAD, 16, 16}},
    {"aes-192-gcm", {AES_GCM, 24, 12, AEAD, 24, 16}},
    {"aes-256-gcm", {AES_GCM, 32, 12, AEAD, 32, 16}}
};

struct Context
{
    bool init_;
    
    CryptoPP::SecByteBlock key_;
    
    size_t iv_length_;
    
    CryptoPP::ChaCha::Encryption cipher_;
};

template<typename T>
struct is_stream : public std::true_type
{
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

struct aes_cfb_enc
{
    CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption enc_;
    CryptoPP::SecByteBlock key_;
    size_t iv_length_;
    bool init_;
    
    aes_cfb_enc(const CryptoPP::SecByteBlock & key, size_t iv_length)
    {
        
    }
    
    void encryt(uint8_t * out, uint8_t * in, size_t size)
    {
        if(!init_)
        {
        }
        enc_.ProcessData(out, in, size);
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

struct chacha_poly1305
{
    CryptoPP::ChaCha20Poly1305::Encryption enc_;
    CryptoPP::ChaCha20Poly1305::Decryption dec_;
    
    void test()
    {
        &CryptoPP::ChaCha20Poly1305::Encryption::EncryptAndAuthenticate;
    }
    
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
