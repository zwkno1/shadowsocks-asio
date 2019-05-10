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

#include <shadowsocks/cipher/error.h>
#include <shadowsocks/cipher/cipher.h>
#include <boost/asio.hpp>

namespace shadowsocks
{
namespace detail
{
        
void increase_iv(CryptoPP::SecByteBlock & iv)
{
    uint16_t c = 1;
    for(auto & i : iv)
    {
        c += i;
        i = c & 0xff;
        c >>= 8;
    }
}

CryptoPP::byte * to_byte(void * p)
{
    return reinterpret_cast<CryptoPP::byte *>(p);
}

const CryptoPP::byte * to_byte(const void * p)
{
    return reinterpret_cast<const CryptoPP::byte *>(p);
}


template<typename Encryption, bool init>
void stream_encrypt_impl(Encryption & enc, const CryptoPP::SecByteBlock & key, size_t iv_length, const CryptoPP::byte * in, size_t in_size, CryptoPP::byte * out)
{
    if constexpr(init)
    {
        CryptoPP::AutoSeededRandomPool{}.GenerateBlock(out, iv_length);
        enc.SetKeyWithIV(key, key.size(), out, iv_length);
        out += iv_length;
    }
    
    enc.ProcessData(out, in, in_size);
}

template<typename Encryption>
void stream_encrypt_all(Encryption & enc, const CryptoPP::SecByteBlock & key, size_t iv_length, boost::asio::const_buffer in, boost::asio::mutable_buffer & out, error_code & ec)
{
    if(out.size() < in.size() + iv_length)
    {
        ec = make_error_code(::shadowsocks::error::cipher_buf_too_short);
        return;
    }
    stream_encrypt_impl<Encryption, true>(enc, key, iv_length, to_byte(in.data()), in.size(), to_byte(out.data()));
    out += in.size() + iv_length;
}

template<typename Encryption>
void stream_encrypt_some(Encryption & enc, const CryptoPP::SecByteBlock & key, size_t iv_length, bool & init, boost::asio::const_buffer & in, boost::asio::mutable_buffer & out, error_code & ec)
{
    if(!init)
    {
        if(out.size() < iv_length)
        {
            ec = make_error_code(::shadowsocks::error::cipher_buf_too_short);
            return;
        }
        
        size_t enc_size = std::min(in.size(), out.size() - iv_length);
        stream_encrypt_impl<Encryption, true>(enc, key, iv_length, to_byte(in.data()), enc_size, to_byte(out.data()));
        init = true;
        out += enc_size + iv_length;
        in += enc_size;
    }
    else
    {
        size_t enc_size = std::min(in.size(), out.size());
        stream_encrypt_impl<Encryption, false>(enc, key, iv_length, to_byte(in.data()), enc_size, to_byte(out.data()));
        out += enc_size;
        in += enc_size;
    }
}
    
template<typename Decryption, bool init>
void stream_decrypt_impl(Decryption & dec, const CryptoPP::SecByteBlock & key, size_t iv_length, const CryptoPP::byte * in, size_t in_size, CryptoPP::byte * out)
{
    if constexpr(init)
    {
        dec.SetKeyWithIV(key.data(), key.size(), in, iv_length);
        in += iv_length;
        in_size -= iv_length;
    }
    
    dec.ProcessData(out, in, in_size); 
}

template<typename Decryption>
void stream_decrypt_all(Decryption & dec, const CryptoPP::SecByteBlock & key, size_t iv_length, boost::asio::const_buffer in, boost::asio::mutable_buffer & out, error_code & ec)
{
    if(in.size() < iv_length)
    {
        ec = make_error_code(::shadowsocks::error::cipher_need_more);
        return;
    }
    
    if(out.size() < in.size() - iv_length)
    {
        ec = make_error_code(::shadowsocks::error::cipher_buf_too_short);
        return;
    }
    
    stream_decrypt_impl<Decryption, true>(dec, key, iv_length, in.data(), in.size(), out.data());
    out += in.size() - iv_length;
}

template<typename Decryption>
void stream_decrypt_some(Decryption & dec, const CryptoPP::SecByteBlock & key, size_t iv_length, bool & init, boost::asio::const_buffer & in, boost::asio::mutable_buffer & out, error_code & ec)
{
    if(!init)
    {
        if(in.size() < iv_length)
        {
            ec = make_error_code(::shadowsocks::error::cipher_need_more);
            return;
        }
        
        size_t dec_size = std::min(in.size() - iv_length, out.size());
        
        stream_decrypt_impl<Decryption, true>(dec, key, iv_length, to_byte(in.data()), dec_size, to_byte(out.data()));
        init = true;
        out += dec_size;
        in += dec_size + iv_length;
    }
    else
    {
        size_t dec_size = std::min(in.size(), out.size());
        stream_decrypt_impl<Decryption, false>(dec, key, iv_length, to_byte(in.data()), dec_size, to_byte(out.data()));
        out += dec_size;
        in += dec_size;
    }
}

template<typename Encryption, bool init>
void aead_encrypt_impl(Encryption & enc, const CryptoPP::SecByteBlock & key, const CryptoPP::SecByteBlock & iv, const CryptoPP::byte * in, size_t in_size, CryptoPP::byte * out)
{
    const size_t tag_length = 16;
    const size_t salt_length = key.size();
    
    if constexpr(init)
    {
        CryptoPP::HKDF<CryptoPP::SHA1> hdfa;
        CryptoPP::SecByteBlock skey{key.size()};
        CryptoPP::AutoSeededRandomPool{}.GenerateBlock(out, salt_length);
        hdfa.DeriveKey(skey, key.size(), key.data(), key.size(), out, salt_length,
            to_byte("ss-subkey"), 9);
        enc.SetKeyWithIV(skey, skey.size(), iv, iv.size());
        out += salt_length;
    }
    
    enc.EncryptAndAuthenticate(out, out + in_size, tag_length,
        iv, iv.size(), nullptr, 0, in, in_size);
}

template<typename Encryption>
void aead_encrypt_all(Encryption & enc, const CryptoPP::SecByteBlock & key, const CryptoPP::SecByteBlock & iv, boost::asio::const_buffer in, boost::asio::mutable_buffer & out, error_code & ec)
{
    const size_t tag_length = 16;
    const size_t salt_length = key.size();
    
    if(out.size() < salt_length + in.size() + tag_length)
    {
        ec = make_error_code(::shadowsocks::error::cipher_buf_too_short);
        return;
    }
    
    aead_encrypt_impl<Encryption, true>(enc, key, iv, in, out);
    out += salt_length + in.size() + tag_length;
}

template<typename Encryption>
void aead_encrypt_some(Encryption & enc, const CryptoPP::SecByteBlock & key,  CryptoPP::SecByteBlock & iv, bool & init, boost::asio::const_buffer & in, boost::asio::mutable_buffer & out, error_code & ec)
{
    const size_t tag_length = 16;
    const size_t salt_length = key.size();
    
    size_t enc_size = std::min(in.size(), max_cipher_block_size);
    
    if(!init)
    {
        if(out.size() < salt_length + enc_size + 2 + tag_length * 2)
        {
            ec = make_error_code(::shadowsocks::error::cipher_buf_too_short);
            return;
        }
        
        std::array<CryptoPP::byte, 2> buf = 
        { 
            static_cast<CryptoPP::byte>((enc_size >> 8) & 0xff), 
            static_cast<CryptoPP::byte>(enc_size & 0xff)
        };
        aead_encrypt_impl<Encryption, true>(enc, key, iv, to_byte(buf.data()), buf.size(), to_byte(out.data()));
        increase_iv(iv);
        init = true;
        out += salt_length + 2 + tag_length;
        
        aead_encrypt_impl<Encryption, false>(enc, key, iv, to_byte(in.data()), enc_size, to_byte(out.data()));
        increase_iv(iv);
        out += enc_size + tag_length;
        
        in += enc_size;
    }
    else
    {
        if(out.size() < enc_size + 2 + tag_length * 2)
        {
            ec = make_error_code(::shadowsocks::error::cipher_buf_too_short);
            return;
        }
        
        std::array<CryptoPP::byte, 2> buf = 
        { 
            static_cast<CryptoPP::byte>((enc_size >> 8) & 0xff), 
            static_cast<CryptoPP::byte>(enc_size & 0xff)
        };
        aead_encrypt_impl<Encryption, false>(enc, key, iv, to_byte(buf.data()), buf.size(), to_byte(out.data()));
        increase_iv(iv);
        out += 2 + tag_length;
        
        aead_encrypt_impl<Encryption, false>(enc, key, iv, to_byte(in.data()), enc_size, to_byte(out.data()));
        increase_iv(iv);
        out += enc_size + tag_length;
        
        in += enc_size;
    }
}

template<typename Decryption, bool init>
bool aead_decrypt_impl(Decryption & dec, const CryptoPP::SecByteBlock & key, const CryptoPP::SecByteBlock & iv, const CryptoPP::byte * in, size_t in_size, CryptoPP::byte * out)
{
    const size_t tag_length = 16;
    const size_t salt_length = key.size();
    
    if constexpr(init)
    {
        CryptoPP::HKDF<CryptoPP::SHA1> hdfa;
        CryptoPP::SecByteBlock skey{key.size()};
        hdfa.DeriveKey(skey, key.size(), key.data(), key.size(), in, salt_length,
            to_byte("ss-subkey"), 9);
        dec.SetKeyWithIV(skey, skey.size(), iv, iv.size());
        in += salt_length;
        in_size -= salt_length;
    }
    
    return dec.DecryptAndVerify(out, in + in_size - tag_length, tag_length, 
        iv, iv.size(), nullptr, 0, in, in_size - tag_length);
}

template<typename Decryption>
void aead_decrypt_all(Decryption & dec, const CryptoPP::SecByteBlock & key, const CryptoPP::SecByteBlock & iv, boost::asio::const_buffer in, boost::asio::mutable_buffer & out, boost::system::error_code & ec)
{
    const size_t tag_length = 16;
    const size_t salt_length = key.size();
    
    if(in.size() <= salt_length + tag_length)
    {
        ec = make_error_code(::shadowsocks::error::cipher_need_more);
        return;
    }
    
    if(out.size() < in.size() - salt_length - tag_length)
    {
        ec = make_error_code(::shadowsocks::error::cipher_buf_too_short);
        return;
    }
    
    if(aead_decrypt_impl<Decryption>(dec, key, iv, to_byte(in.data()), in.size(), to_byte(out.data())))
    {
        ec = make_error_code(::shadowsocks::error::cipher_aead_decrypt_verify_failed);
        return;
    }
    out += in.size() - salt_length - tag_length;
}

template<typename Decryption>
void aead_decrypt_some(Decryption & dec, const CryptoPP::SecByteBlock & key, CryptoPP::SecByteBlock & iv, bool & init, size_t & block_size, boost::asio::const_buffer & in, boost::asio::mutable_buffer & out, boost::system::error_code & ec)
{
    const size_t tag_length = 16;
    const size_t salt_length = key.size();
    
    for(;;)
    {
        if(block_size == 0)
        {
            std::array<CryptoPP::byte, 2> buf;
            const size_t dec_size = buf.size() + tag_length + (init ? 0 : salt_length);
            if(in.size() < dec_size)
            {
                ec = make_error_code(::shadowsocks::error::cipher_need_more);
                return;
            }
            
            bool result;
            if(!init)
            {
                result = aead_decrypt_impl<Decryption, true>(dec, key, iv, to_byte(in.data()), dec_size, to_byte(buf.data()));
                init = true;
            }
            else
            {
                result = aead_decrypt_impl<Decryption, false>(dec, key, iv, to_byte(in.data()), dec_size, to_byte(buf.data()));
            }
            
            if(!result)
            {
                ec = make_error_code(::shadowsocks::error::cipher_aead_decrypt_verify_failed);
                return;
            }
            increase_iv(iv);
            
            block_size = buf[0] << 8 | buf[1];
            if((block_size == 0) || (block_size > max_cipher_block_size))
            {
                ec = make_error_code(::shadowsocks::error::cipher_aead_invalid_block_size);
                return;
            }
            
            in += dec_size;
        }
        else
        {
            const size_t dec_size = block_size + tag_length;
            
            if(in.size() < dec_size)
            {
                ec = make_error_code(::shadowsocks::error::cipher_need_more);
                return;
            }
            
            if(out.size() < block_size)
            {
                ec = make_error_code(::shadowsocks::error::cipher_buf_too_short);
                return;
            }
            
            if(!aead_decrypt_impl<Decryption, false>(dec, key, iv, to_byte(in.data()), dec_size, to_byte(out.data())))
            {
                ec = make_error_code(::shadowsocks::error::cipher_aead_decrypt_verify_failed);
                return;
            }
            increase_iv(iv);
            
            in += dec_size;
            out += block_size;
            
            block_size = 0;
        }
    }
}

}
}
