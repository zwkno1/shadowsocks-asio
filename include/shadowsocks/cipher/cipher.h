#pragma once

#include <cstdint>
#include <memory>
#include <variant>
#include <unordered_map>
#include <type_traits>

#include <shadowsocks/detail/cipher/cipher.h>

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
    AES_CTR,
    BLOWFISH_CFB,
    CAMELLIA_CFB,
    CAST_CFB,
    CHACHA20,
    CHACHA20_IETF,
    DES_CFB,
    IDEA_CFB,
    RC2_CFB,
    RC4_MD5,
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

using cipher_key = CryptoPP::SecByteBlock;

inline const cipher_info * make_cipher_info(const std::string & name)
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
        {"chacha20-ietf", {CHACHA20_IETF, 32, 12, STREAM}},
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

inline cipher_key make_cipher_key(const shadowsocks::cipher_info & info, const std::string & password)
{
    cipher_key key;
    for(int i = 0; key.size() < info.key_length_; ++i)
    {
        CryptoPP::Weak1::MD5 md5;
        if (i != 0)
        {
            md5.Update(&key[(i-1)*16], 16);
        }
        md5.Update(reinterpret_cast<const uint8_t * >(password.data()), password.size());
        key.resize((i+1)*16);
        md5.Final(&key[i*16]);
    }
    
    key.resize(info.key_length_);
    return key;
}

namespace detail{

using cipher_impl = std::variant<
    stream_cipher<CryptoPP::CFB_Mode<CryptoPP::AES>>,
    stream_cipher<CryptoPP::CTR_Mode<CryptoPP::AES>>,
    stream_cipher<CryptoPP::CFB_Mode<CryptoPP::Blowfish>>,
    stream_cipher<CryptoPP::CFB_Mode<CryptoPP::Camellia>>,
    stream_cipher<CryptoPP::CFB_Mode<CryptoPP::CAST128>>,
    stream_cipher<CryptoPP::ChaCha>,
    stream_cipher<CryptoPP::ChaChaTLS>,
    stream_cipher<CryptoPP::CFB_Mode<CryptoPP::DES>>,
    stream_cipher<CryptoPP::CFB_Mode<CryptoPP::IDEA>>,
    stream_cipher<CryptoPP::CFB_Mode<CryptoPP::RC2>>,
    //stream_cipher<CryptoPP::ARC4>,
    stream_cipher<CryptoPP::Salsa20>,
    stream_cipher<CryptoPP::CFB_Mode<CryptoPP::SEED>>,
    stream_cipher<CryptoPP::CFB_Mode<CryptoPP::Serpent>>,
    // AEAD
    aead_cipher<CryptoPP::ChaCha20Poly1305>,
    aead_cipher<CryptoPP::XChaCha20Poly1305>,
    aead_cipher<CryptoPP::GCM<CryptoPP::AES>>,
    null_cipher
    >;


template<typename ... Args>
void make_stream_cipher(cipher_impl & cipher, cipher_metod method, Args ...args) 
{
    switch(method)
    {
        case AES_CFB:
            cipher.emplace<stream_cipher<CryptoPP::CFB_Mode<CryptoPP::AES>>>(std::forward<Args>(args)...);
            return;
        case AES_CTR:
            cipher.emplace<stream_cipher<CryptoPP::CTR_Mode<CryptoPP::AES>>>(std::forward<Args>(args)...);
            return;
        case BLOWFISH_CFB:
            cipher.emplace<stream_cipher<CryptoPP::CFB_Mode<CryptoPP::Blowfish>>>(std::forward<Args>(args)...);
            return;
        case CAMELLIA_CFB:
            cipher.emplace<stream_cipher<CryptoPP::CFB_Mode<CryptoPP::Camellia>>>(std::forward<Args>(args)...);
            return;
        case CAST_CFB:
            cipher.emplace<stream_cipher<CryptoPP::CFB_Mode<CryptoPP::CAST128>>>(std::forward<Args>(args)...);
            return;
        case CHACHA20:
            cipher.emplace<stream_cipher<CryptoPP::ChaCha>>(std::forward<Args>(args)...);
            return;
        case CHACHA20_IETF:
            cipher.emplace<stream_cipher<CryptoPP::ChaChaTLS>>(std::forward<Args>(args)...);
            return;
        case DES_CFB:
            cipher.emplace<stream_cipher<CryptoPP::CFB_Mode<CryptoPP::DES>>>(std::forward<Args>(args)...);
            return;
        case IDEA_CFB:
            cipher.emplace<stream_cipher<CryptoPP::CFB_Mode<CryptoPP::IDEA>>>(std::forward<Args>(args)...);
            return;
        case RC2_CFB:
            cipher.emplace<stream_cipher<CryptoPP::CFB_Mode<CryptoPP::RC2>>>(std::forward<Args>(args)...);
            return;
        //case RC4_MD5:
        //    cipher.empalce<stream_cipher<CryptoPP::ARC4>>(std::forward<Args>(args)...);
        //    return;
        case SALSA20:
            cipher.emplace<stream_cipher<CryptoPP::Salsa20>>(std::forward<Args>(args)...);
            return;
        case SEED_CFB:
            cipher.emplace<stream_cipher<CryptoPP::CFB_Mode<CryptoPP::SEED>>>(std::forward<Args>(args)...);
            return;
        case SERPENT_CFB:
            cipher.emplace<stream_cipher<CryptoPP::CFB_Mode<CryptoPP::Serpent>>>(std::forward<Args>(args)...);
            return;
        default:
            throw shadowsocks::error::make_error_code(shadowsocks::error::cipher_algo_not_found);
    }
}

template<typename ... Args>
void make_aead_cipher(cipher_impl & cipher, cipher_metod method, Args ...args) 
{
    switch(method)
    {
        case CHACHA20_POLY1305:
            cipher.emplace<aead_cipher<CryptoPP::ChaCha20Poly1305>>(std::forward<Args>(args)...);
            return;
        case XCHACHA20_POLY1305:
            cipher.emplace<aead_cipher<CryptoPP::XChaCha20Poly1305>>(std::forward<Args>(args)...);
            return;
        case AES_GCM:
            cipher.emplace<aead_cipher<CryptoPP::GCM<CryptoPP::AES>>>(std::forward<Args>(args)...);
            return;
        default:
            throw shadowsocks::error::make_error_code(shadowsocks::error::cipher_algo_not_found);
    }
}

void make_cipher_impl(cipher_impl & cipher, const cipher_info & info, const cipher_key & key)
{
    if (info.type_ == STREAM) {
        return make_stream_cipher(cipher, info.method_, key, info.iv_length_);
    } else {
        return make_aead_cipher(cipher, info.method_, key, info.key_length_, info.iv_length_);
    }  
}  

} // namespace detail


class cipher_context {
public:
    template<typename ...Args>
    cipher_context(Args ...args)
        : impl_(detail::null_cipher{})
    {
        detail::make_cipher_impl(impl_, std::forward<Args>(args)...);
    }

    inline void encrypt(asio::const_buffer input, asio::streambuf & output)
    {
      std::visit([&](auto &&arg) { arg.encrypt(input, output); }, impl_);
    }

    void decrypt(asio::streambuf & input, asio::mutable_buffer output, error_code & ec, size_t & nbytes) 
    {
      std::visit([&](auto &&arg) { arg.decrypt(input, output, ec, nbytes); }, impl_);
    }

private:
    detail::cipher_impl impl_;
};

} // namespace shadowsocks
