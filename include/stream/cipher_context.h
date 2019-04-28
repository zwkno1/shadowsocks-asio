#pragma once

#include <variant>
#include <unordered_map>
#include <type_traits>

#include <stream/detail/cipher.h>
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
    DES_CFB,
    IDEA_CFB,
    RC2_CFB,
    //RC4_MD5,
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
struct cipher_pair_type_traits : public std::integral_constant<cipher_type, (std::is_same<T, cipher_pair<CryptoPP::ChaCha20Poly1305>>::value || std::is_same<T, CryptoPP::GCM<CryptoPP::AES>>::value ? AEAD : STREAM)>
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
    cipher_pair<CryptoPP::ChaCha20Poly1305>,
    cipher_pair<CryptoPP::GCM<CryptoPP::AES>>
    > cipher_pair_variant;
    
cipher_pair_variant make_cipher_pair(cipher_metod m)
{
    switch(m)
    {
        case AES_CFB:
            return cipher_pair<CryptoPP::CFB_Mode<CryptoPP::AES>>{};
        case AES_CTR_BE:
            return cipher_pair<CryptoPP::CTR_Mode<CryptoPP::AES>>{};
        case BLOWFISH_CFB:
            return cipher_pair<CryptoPP::CFB_Mode<CryptoPP::Blowfish>>{};
        case CAMELLIA_CFB:
            return cipher_pair<CryptoPP::CFB_Mode<CryptoPP::Camellia>>{};
        case CAST_CFB:
            return cipher_pair<CryptoPP::CFB_Mode<CryptoPP::CAST128>>{};
        case CHACHA20:
            return cipher_pair<CryptoPP::ChaCha>{};
        case DES_CFB:
            return cipher_pair<CryptoPP::CFB_Mode<CryptoPP::DES>>{};
        case IDEA_CFB:
            return cipher_pair<CryptoPP::CFB_Mode<CryptoPP::IDEA>>{};
        case RC2_CFB:
            return cipher_pair<CryptoPP::CFB_Mode<CryptoPP::RC2>>{};
        //case RC4_MD5:
        //    return cipher_pair<CryptoPP::ARC4>{};
        case SALSA20:
            return cipher_pair<CryptoPP::Salsa20>{};
        case SEED_CFB:
            return cipher_pair<CryptoPP::CFB_Mode<CryptoPP::SEED>>{};
        case CHACHA20_POLY1305:
            return cipher_pair<CryptoPP::CFB_Mode<CryptoPP::Serpent>>{};
        case SERPENT_CFB:
            return cipher_pair<CryptoPP::ChaCha20Poly1305>{};
        case AES_GCM:
            return cipher_pair<CryptoPP::GCM<CryptoPP::AES>>{};
    }
}

}

class cipher_context
{
public:
    cipher_context(const cipher_info & info, const std::vector<uint8_t> & key)
        : info_(info)
        , key_(key.data(), key.size())
    {
        cipher_ = detail::make_cipher_pair(info.method_);
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
                detail::encrypt(arg.encryption, enc_ctx_.init, key_, info_.iv_length_, in, in_size, write_buf_.data(), write_buf_size_ );
            }
            else
            {
                detail::encrypt(arg.encryption, enc_ctx_.init, key_, enc_ctx_.iv, info_.iv_length_, in, in_size, write_buf_.data(), write_buf_size_ );
            }
        }, cipher_);
    }
    
    void decrypt(uint8_t *out, size_t & out_size, boost::system::error_code & ec)
    {
        std::visit([&](auto&& arg)
        {
            size_t read_buf_size = read_buf_size_;
            if constexpr(detail::cipher_pair_type_traits<decltype(arg)>::value == STREAM)
            {
                detail::decrypt(arg.decryption, dec_ctx_.init, key_, info_.iv_length_, read_buf_.data(), read_buf_size, out, out_size);
            }
            else
            {
                detail::decrypt(arg.decryption, dec_ctx_.init, key_, dec_ctx_.iv, dec_size_, read_buf_.data(), read_buf_size, out, out_size, ec);
            }
            read_buf_size_ -= read_buf_size;
            
            if((read_buf_size != 0) && (read_buf_size_ != 0))
            {
                std::memcpy(read_buf_.data(), read_buf_.data() + read_buf_size, read_buf_size_);
            }
        }, cipher_);
    }
    
private:
    const cipher_info & info_;
    
    detail::cipher_pair_variant cipher_;
    
    CryptoPP::SecByteBlock key_;
    
    struct context
    {
        bool init;
        CryptoPP::SecByteBlock iv;
    };
    
    context enc_ctx_;
    context dec_ctx_;
    size_t dec_size_;
    
    std::array<uint8_t, 0x4ff> write_buf_;
    size_t write_buf_size_;
    std::array<uint8_t, 0x4ff> read_buf_;
    size_t read_buf_size_;
};

}
