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

#include <shadowsocks/cipher/cipher.h>
#include <shadowsocks/cipher/detail/cipher_ops.h>
#include <shadowsocks/cipher/error.h>

namespace shadowsocks
{
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
    
    void encrypt(boost::asio::const_buffer & in, boost::system::error_code & ec)
    {
        boost::asio::mutable_buffer out{write_buf_.data() + write_buf_size_, write_buf_.size() - write_buf_size_};
        
        std::visit([&](auto&& arg)
        {
            if constexpr(cipher_pair_type_traits<decltype(arg)>::value == STREAM)
            {
                stream_encrypt_some(arg.encryption, key_, info_.iv_length_, enc_init_, in, out, ec);
            }
            else
            {
                aead_encrypt_some(arg.encryption, key_, enc_iv_, enc_init_, in, out, ec);
            }
        }, cipher_);
        
        write_buf_size_ = write_buf_.size() - out.size();
    }
    
    void decrypt(boost::asio::mutable_buffer & out, boost::system::error_code & ec)
    {
        boost::asio::const_buffer in{ read_buf_.data(), read_buf_size_};
        
        std::visit([&](auto&& arg)
        {
            if constexpr(cipher_pair_type_traits<decltype(arg)>::value == STREAM)
            {
                stream_decrypt_some(arg.decryption, key_, info_.iv_length_, dec_init_, in, out, ec);
            }
            else
            {
                aead_decrypt_some(arg.decryption, key_, dec_iv_, dec_init_, dec_block_size_, in, out, ec);
            }
        }, cipher_);
        
        if((read_buf_size_ != in.size()) && in.size() != 0)
        {
            std::memmove(read_buf_.data(), in.data(), in.size());
        }
        read_buf_size_ = in.size();
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
}
