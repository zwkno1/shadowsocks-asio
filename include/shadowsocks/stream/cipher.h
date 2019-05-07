#pragma once

#include <variant>
#include <type_traits>

#include <boost/asio.hpp>
#include <boost/noncopyable.hpp>

#ifndef CRYPTOPP_ENABLE_NAMESPACE_WEAK 
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/md5.h>
#undef CRYPTOPP_ENABLE_NAMESPACE_WEAK
#else
#include <cryptopp/md5.h>
#endif

namespace shadowsocks
{
    
enum : std::size_t
{
    max_cipher_block_size = 0x3fff,
};

enum cipher_type : uint8_t
{
    STREAM,
    AEAD
};

enum cipher_metod
{
    AES_CFB,
    AES_CTR,
    BLOWFISH_CFB,
    CAMELLIA_CFB,
    CAST_CFB,
    CHACHA20,
    DES_CFB,
    IDEA_CFB,
    RC2_CFB,
    //RC4_MD5,
    SALSA20,
    SEED_CFB,
    SERPENT_CFB,
    CHACHA20_POLY1305,
    XCHACHA20_POLY1305,
    AES_GCM,
};

struct cipher_info 
{
    cipher_metod method_;
    size_t key_length_;
    size_t iv_length_;
    cipher_type type_;
    
    // now same with key_length_
    //size_t salt_length_; // only for AEAD
    // now fixed 16 
    //size_t tag_length_; // only for AEAD
};

inline const cipher_info * get_cipher_info(const std::string & name)
{
    static const std::unordered_map<std::string, cipher_info> cipher_infos = 
    {
        {"aes-128-cfb", {AES_CFB, 16, 16, STREAM}},
        {"aes-192-cfb", {AES_CFB, 24, 16, STREAM}},
        {"aes-256-cfb", {AES_CFB, 32, 16, STREAM}},
        {"aes-128-ctr", {AES_CTR, 16, 16, STREAM}},
        {"aes-192-ctr", {AES_CTR, 24, 16, STREAM}},
        {"aes-256-ctr", {AES_CTR, 32, 16, STREAM}},
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
        //{"rc4-md5", {RC4_MD5, 16, 16, STREAM}},
        {"salsa20", {SALSA20, 32, 8, STREAM}},
        {"seed-cfb", {SEED_CFB, 16, 16, STREAM}},
        {"serpent-256-cfb", {SERPENT_CFB, 32, 16, STREAM}},
        {"chacha20-ietf-poly1305", {CHACHA20_POLY1305, 32, 12, AEAD/*, 32, 16*/}},
        {"xchacha20-ietf-poly1305", {XCHACHA20_POLY1305, 32, 24, AEAD/*, 32, 16*/}},
        {"aes-128-gcm", {AES_GCM, 16, 12, AEAD/*, 16, 16*/}},
        {"aes-192-gcm", {AES_GCM, 24, 12, AEAD/*, 24, 16*/}},
        {"aes-256-gcm", {AES_GCM, 32, 12, AEAD/*, 32, 16*/}}
    };
    
    auto iter = cipher_infos.find(name);
    if(iter == cipher_infos.end())
    {
        return nullptr;
    }
    
    return &iter->second;
}

inline std::vector<uint8_t> build_cipher_key(const shadowsocks::cipher_info & info, const std::string & password)
{
    std::vector<uint8_t> result;
    for(int i = 0; result.size() < info.key_length_; ++i)
    {
        CryptoPP::Weak1::MD5 md5;
        if (i != 0)
        {
            md5.Update(&result[(i-1)*16], 16);
        }
        md5.Update(reinterpret_cast<const uint8_t * >(password.data()), password.size());
        result.resize((i+1)*16);
        md5.Final(&result[i*16]);
    }
    
    result.resize(info.key_length_);
    return result;
}

}
