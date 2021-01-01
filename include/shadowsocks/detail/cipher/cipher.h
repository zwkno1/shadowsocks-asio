#pragma once

#include <cryptopp/cryptlib.h>
#include <cryptopp/secblock.h>
#include <cryptopp/osrng.h>
#include <cryptopp/aes.h>
#include <cryptopp/blowfish.h>
#include <cryptopp/camellia.h>
#include <cryptopp/chacha.h>
#include <cryptopp/cast.h>
#include <cryptopp/chacha.h>
#include <cryptopp/des.h>
#include <cryptopp/idea.h>
#include <cryptopp/rc2.h>
#include <cryptopp/salsa.h>
#include <cryptopp/seed.h>
#include <cryptopp/serpent.h>
#include <cryptopp/hkdf.h>
#include <cryptopp/sha.h>
#include <cryptopp/modes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/chachapoly.h>
#ifndef CRYPTOPP_ENABLE_NAMESPACE_WEAK 
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/arc4.h>
#include <cryptopp/md5.h>
#endif

#include <shadowsocks/cipher/error.h>
#include <shadowsocks/asio.h>

namespace shadowsocks
{

constexpr size_t MAX_AEAD_BLOCK_SIZE = 0x3fff;

namespace detail
{
        
CryptoPP::byte * to_byte(void * p)
{
    return reinterpret_cast<CryptoPP::byte *>(p);
}

const CryptoPP::byte * to_byte(const void * p)
{
    return reinterpret_cast<const CryptoPP::byte *>(p);
}

class null_cipher 
{
public:
    null_cipher()
    {
    }

    void encrypt(asio::const_buffer input, asio::streambuf & output)
    {
    }

    void decrypt(asio::streambuf & input, asio::mutable_buffer output, error_code & ec, size_t & nbytes) 
    {
    }
};

template <typename T>
class stream_cipher
{
    using encryption_type = typename T::Encryption;
    using decryption_type = typename T::Decryption;
public:
    stream_cipher(const CryptoPP::SecByteBlock & key, size_t iv_length) 
        : key_(key)
        , iv_length_(iv_length)
        , encryption_init_(false)
        , decryption_init_(false)
    {
    }

    void encrypt(asio::const_buffer input, asio::streambuf & output)
    {
        size_t encryption_size = input.size() + (encryption_init_ ? 0 : iv_length_);
        auto wpos = to_byte(output.prepare(encryption_size).data());
        if(!encryption_init_) {
            CryptoPP::AutoSeededRandomPool{}.GenerateBlock(wpos, iv_length_);
            encryption_.SetKeyWithIV(key_.data(), key_.size(), wpos, iv_length_);
            encryption_init_ = true;
            wpos += iv_length_;
        }
        encryption_.ProcessData(wpos, to_byte(input.data()), input.size());
        output.commit(encryption_size);
    }

    void decrypt(asio::streambuf & input, asio::mutable_buffer output, error_code & ec, size_t & nbytes) 
    {
        nbytes = 0;
        auto rbuf = input.data();
        if(!decryption_init_) {
            if(rbuf.size() < iv_length_) {
                return;
            }
            decryption_.SetKeyWithIV(key_, key_.size(), to_byte(rbuf.data()), iv_length_);
            decryption_init_ = true;
            rbuf += iv_length_;
        }

        if(rbuf.size() > 0) {
          nbytes = std::min(output.size(), rbuf.size());
          decryption_.ProcessData(to_byte(output.data()), to_byte(rbuf.data()), nbytes);
        }

        input.consume(input.size());
    }

private:
    encryption_type encryption_;

    decryption_type decryption_;
    
    CryptoPP::SecByteBlock key_; 
    
    size_t iv_length_;
    
    bool encryption_init_;
    
    bool decryption_init_;
};

template <typename T>
class aead_cipher
{
    using encryption_type = typename T::Encryption;

    using decryption_type = typename T::Decryption;
    
    static constexpr size_t TAG_LENGTH = 16; 

public:
    aead_cipher(const CryptoPP::SecByteBlock & key, size_t salt_length, size_t iv_length) 
        : key_(key)
        , salt_length_(salt_length)
        , encryption_init_(false)
        , decryption_init_(false)
        , block_size_(0)
    {
        encryption_iv_.Assign(iv_length, 0);
        decryption_iv_.Assign(iv_length, 0);
    }

    void encrypt(asio::const_buffer input, asio::streambuf & output)
    {
        const size_t encryption_size = [&]() {
            size_t nblocks = (input.size() + MAX_AEAD_BLOCK_SIZE - 1) / MAX_AEAD_BLOCK_SIZE;
            size_t init_size = (encryption_init_ ? 0 : salt_length_);
            return init_size + nblocks * (2 + TAG_LENGTH + TAG_LENGTH) + input.size();
        }();

        auto wpos = to_byte(output.prepare(encryption_size).data());
        if (!encryption_init_) {
            CryptoPP::HKDF<CryptoPP::SHA1> hdfa;
            CryptoPP::SecByteBlock skey{key_.size()};
            CryptoPP::AutoSeededRandomPool{}.GenerateBlock(wpos, salt_length_);
            hdfa.DeriveKey(skey, skey.size(), key_.data(), key_.size(), wpos, salt_length_, to_byte("ss-subkey"), 9);
            encryption_.SetKeyWithIV(skey, skey.size(), encryption_iv_, encryption_iv_.size());
            encryption_init_ = true;
            wpos += salt_length_;
        }

        while(input.size() != 0)
        {
            const size_t block_size = std::min(MAX_AEAD_BLOCK_SIZE, input.size());
            CryptoPP::byte length_buffer[2] = { 
                static_cast<CryptoPP::byte>((block_size >> 8) & 0xff),
                static_cast<CryptoPP::byte>(block_size & 0xff)
            };
            encrypt_block(wpos, length_buffer, 2);
            wpos += 2 + TAG_LENGTH;
            encrypt_block(wpos, to_byte(input.data()), block_size);
            wpos += block_size + TAG_LENGTH; 
            input += block_size;
        }
        output.commit(encryption_size);
    }

    void decrypt(asio::streambuf & input, asio::mutable_buffer output, error_code & ec, size_t & nbytes) 
    {
        nbytes = 0;
        auto rbuf = input.data();
        if (!decryption_init_) {
            if(input.size() < salt_length_) {
                return;
            }
            CryptoPP::HKDF<CryptoPP::SHA1> hdfa;
            CryptoPP::SecByteBlock skey{key_.size()};
            hdfa.DeriveKey(skey, skey.size(), key_.data(), key_.size(), to_byte(rbuf.data()), salt_length_, to_byte("ss-subkey"), 9); 
            decryption_.SetKeyWithIV(skey, skey.size(), decryption_iv_.data(), decryption_iv_.size());
            decryption_init_ = true;
            rbuf += salt_length_;
            input.consume(salt_length_);
        }

        for (;;) {
            const size_t decryption_size = (block_size_ == 0 ? 2 : block_size_) + TAG_LENGTH;
            if(rbuf.size() < decryption_size) {
                break;
            }

            if (block_size_ == 0) {
                CryptoPP::byte length_buffer[2];
                if(!decrypt_block(length_buffer, to_byte(rbuf.data()), decryption_size)){
                    ec =  error::make_error_code(error::cipher_aead_decrypt_verify_failed);
                    break;
                }
                block_size_ = length_buffer[0] << 8 | length_buffer[1];
                if ((block_size_ == 0) || (block_size_ > MAX_AEAD_BLOCK_SIZE)) {
                    ec = make_error_code(error::cipher_aead_invalid_block_size);
                    break;
                }
            } else {
                if(output.size() < block_size_) {
                    if(nbytes == 0) {
                        ec = error::make_error_code(error::cipher_buffer_too_short);
                    }
                    break;
                }
                if(!decrypt_block(to_byte(output.data()), to_byte(rbuf.data()), decryption_size)) {
                    ec =  error::make_error_code(error::cipher_aead_decrypt_verify_failed);
                    break;
                }
                output += block_size_;
                nbytes += block_size_;
                block_size_ = 0;
            }
            rbuf += decryption_size;
        }

        input.consume(input.size() - rbuf.size());
    }

private:
    inline void encrypt_block(CryptoPP::byte * output, const CryptoPP::byte * data, size_t size)
    {
        encryption_.EncryptAndAuthenticate(output, output + size, TAG_LENGTH, encryption_iv_, encryption_iv_.size(), nullptr, 0, data, size);
        increase_iv(encryption_iv_);
    }

    inline bool decrypt_block(CryptoPP::byte * output, const CryptoPP::byte * data, size_t size)
    {
        bool result = decryption_.DecryptAndVerify(output, data + size - TAG_LENGTH, TAG_LENGTH, decryption_iv_, decryption_iv_.size(), nullptr, 0, data, size - TAG_LENGTH);
        increase_iv(decryption_iv_);
        return result;
    }

    inline void increase_iv(CryptoPP::SecByteBlock &iv) 
    {
        uint16_t c = 1;
        for (auto &i : iv) {
            c += i;
            i = c & 0xff;
            c >>= 8;
        }
    }

    encryption_type encryption_;

    decryption_type decryption_;

    CryptoPP::SecByteBlock key_; 

    size_t salt_length_;

    bool encryption_init_;

    bool decryption_init_;

    CryptoPP::SecByteBlock encryption_iv_; 

    CryptoPP::SecByteBlock decryption_iv_; 

    size_t block_size_;
};

} // namespace detail
} // namespace shadowsocks
