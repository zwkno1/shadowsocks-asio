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

#include <spdlog/spdlog.h>

#include <stream/detail/cipher.h>
#include <stream/error.h>

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

namespace detail
{
    
template<typename T>
struct cipher_pair
{
    typedef typename T::Encryption encryption_type;
    typedef typename T::Decryption decryption_type;
    
    encryption_type encryption;
    
    decryption_type decryption;
};

template<typename T>
struct cipher_pair_type_traits 
    : public std::integral_constant<cipher_type, (
        std::is_same<std::decay_t<T>, cipher_pair<CryptoPP::ChaCha20Poly1305>>::value 
        || std::is_same<std::decay_t<T>, cipher_pair<CryptoPP::XChaCha20Poly1305>>::value 
        || std::is_same<std::decay_t<T>, cipher_pair<CryptoPP::GCM<CryptoPP::AES>>>::value
    ) ? AEAD : STREAM >
{
};

typedef std::variant<
    cipher_pair<CryptoPP::CFB_Mode<CryptoPP::AES>>,
    cipher_pair<CryptoPP::CTR_Mode<CryptoPP::AES>>,
    cipher_pair<CryptoPP::CFB_Mode<CryptoPP::Blowfish>>,
    cipher_pair<CryptoPP::CFB_Mode<CryptoPP::Camellia>>,
    cipher_pair<CryptoPP::CFB_Mode<CryptoPP::CAST128>>,
    cipher_pair<CryptoPP::ChaCha>,
    cipher_pair<CryptoPP::CFB_Mode<CryptoPP::DES>>,
    cipher_pair<CryptoPP::CFB_Mode<CryptoPP::IDEA>>,
    cipher_pair<CryptoPP::CFB_Mode<CryptoPP::RC2>>,
    //cipher_pair<CryptoPP::ARC4>,
    cipher_pair<CryptoPP::Salsa20>,
    cipher_pair<CryptoPP::CFB_Mode<CryptoPP::SEED>>,
    cipher_pair<CryptoPP::CFB_Mode<CryptoPP::Serpent>>,
    // AEAD
    // !!! if you add a aead method, don't forget to add it in cipher_pair_type_traits !!!
    cipher_pair<CryptoPP::ChaCha20Poly1305>,
    cipher_pair<CryptoPP::XChaCha20Poly1305>,
    cipher_pair<CryptoPP::GCM<CryptoPP::AES>>
    > cipher_pair_variant;

void make_cipher_pair(cipher_metod m, cipher_pair_variant & v)
{
    switch(m)
    {
        case AES_CFB:
            v.emplace<cipher_pair<CryptoPP::CFB_Mode<CryptoPP::AES>>>();
            break;
        case AES_CTR:
            v.emplace<cipher_pair<CryptoPP::CTR_Mode<CryptoPP::AES>>>();
            break;
        case BLOWFISH_CFB:
            v.emplace<cipher_pair<CryptoPP::CFB_Mode<CryptoPP::Blowfish>>>();
            break;
        case CAMELLIA_CFB:
            v.emplace<cipher_pair<CryptoPP::CFB_Mode<CryptoPP::Camellia>>>();
            break;
        case CAST_CFB:
            v.emplace<cipher_pair<CryptoPP::CFB_Mode<CryptoPP::CAST128>>>();
            break;
        case CHACHA20:
            v.emplace<cipher_pair<CryptoPP::ChaCha>>();
            break;
        case DES_CFB:
            v.emplace<cipher_pair<CryptoPP::CFB_Mode<CryptoPP::DES>>>();
            break;
        case IDEA_CFB:
            v.emplace<cipher_pair<CryptoPP::CFB_Mode<CryptoPP::IDEA>>>();
            break;
        case RC2_CFB:
            v.emplace<cipher_pair<CryptoPP::CFB_Mode<CryptoPP::RC2>>>();
            break;
        //case RC4_MD5:
        //    return cipher_pair<CryptoPP::ARC4>{};
        case SALSA20:
            v.emplace<cipher_pair<CryptoPP::Salsa20>>();
            break;
        case SEED_CFB:
            v.emplace<cipher_pair<CryptoPP::CFB_Mode<CryptoPP::SEED>>>();
            break;
        case SERPENT_CFB:
            v.emplace<cipher_pair<CryptoPP::CFB_Mode<CryptoPP::Serpent>>>();
            break;
        case CHACHA20_POLY1305:
            v.emplace<cipher_pair<CryptoPP::ChaCha20Poly1305>>();
            break;
        case XCHACHA20_POLY1305:
            v.emplace<cipher_pair<CryptoPP::XChaCha20Poly1305>>();
            break;
        case AES_GCM:
            v.emplace<cipher_pair<CryptoPP::GCM<CryptoPP::AES>>>();
            break;
        default:
            throw shadowsocks::error::make_error_code(shadowsocks::error::cipher_algo_not_found);
    }
}

}

const cipher_info * get_cipher_info(const std::string & name)
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

std::vector<uint8_t> get_cipher_key(const shadowsocks::cipher_info & info, const std::string &password)
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

class cipher_context : private boost::noncopyable
{
public:
    cipher_context(const cipher_info & info, const std::vector<uint8_t> & key)
        : info_(info)
        , key_(key.data(), key.size())
    {
        make_cipher_pair(info.method_, cipher_);
        
        enc_iv_.Assign(info.iv_length_, 0);
        dec_iv_.Assign(info.iv_length_, 0);
    }
    
    boost::asio::mutable_buffer get_read_buffer()
    {
        return boost::asio::mutable_buffer{read_buf_.data() + read_buf_size_, read_buf_.size() - read_buf_size_};
    }
    
    boost::asio::const_buffer get_write_buffer()
    {
        return boost::asio::const_buffer{write_buf_.data(), write_buf_size_};
    }
    
    void handle_read(size_t bytes)
    {
        read_buf_size_ += bytes;
    }
    
    void handle_write()
    {
        write_buf_size_ = 0;
    }
    
    void encrypt(const uint8_t * in, size_t & in_size)
    {
        std::visit([&](auto&& arg)
        {
            if constexpr(detail::cipher_pair_type_traits<decltype(arg)>::value == STREAM)
            {
                detail::encrypt(arg.encryption, enc_init_, key_, info_.iv_length_, in, in_size, write_buf_.data(), write_buf_size_);
            }
            else
            {
                detail::encrypt(arg.encryption, enc_init_, key_, enc_iv_, in, in_size, write_buf_.data(), write_buf_size_);
            }
        }, cipher_);
    }
    
    void decrypt(uint8_t *out, size_t & out_size, boost::system::error_code & ec)
    {
        std::visit([&](auto&& arg)
        {
            size_t dec_size = read_buf_size_;
            if constexpr(detail::cipher_pair_type_traits<decltype(arg)>::value == STREAM)
            {
                detail::decrypt(arg.decryption, dec_init_, key_, info_.iv_length_, read_buf_.data(), dec_size, out, out_size);
            }
            else
            {
                detail::decrypt(arg.decryption, dec_init_, key_, dec_iv_, dec_block_size_, read_buf_.data(), dec_size, out, out_size, ec);
            }
            read_buf_size_ -= dec_size;
            
            if((dec_size != 0) && (read_buf_size_ != 0))
            {
                std::memmove(read_buf_.data(), read_buf_.data() + dec_size, read_buf_size_);
            }
        }, cipher_);
    }
    
private:
    const cipher_info & info_;
    
    detail::cipher_pair_variant cipher_;
    
    CryptoPP::SecByteBlock key_;
    
    bool enc_init_ = false;
    CryptoPP::SecByteBlock enc_iv_;
    
    bool dec_init_ = false;
    CryptoPP::SecByteBlock dec_iv_;
    size_t dec_block_size_ = 0;
    
    std::array<uint8_t, max_cipher_block_size + 1024> write_buf_;
    size_t write_buf_size_ = 0;
    std::array<uint8_t, max_cipher_block_size + 1024> read_buf_;
    size_t read_buf_size_ = 0;
};

}
