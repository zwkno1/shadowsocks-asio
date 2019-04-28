#pragma once

#include <iostream>

#include <cryptopp/cryptlib.h>
#include <cryptopp/secblock.h>
#include <cryptopp/chacha.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>
#include <cryptopp/hex.h>
#include <cryptopp/aes.h>
#include <cryptopp/blowfish.h>
#include <cryptopp/camellia.h>
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

#include <stream/error.h>

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

template<typename Encryption>
void encrypt(Encryption & enc, bool & init, const CryptoPP::SecByteBlock & key, size_t iv_length, const uint8_t * in, size_t & in_size, uint8_t * out, size_t & out_size)
{
    out_size = 0;
    if(!init)
    {
        CryptoPP::byte * iv = reinterpret_cast<CryptoPP::byte *>(out);
        CryptoPP::AutoSeededRandomPool{}.GenerateBlock(iv, iv_length);
        enc.SetKeyWithIV(key, key.size(), iv, iv_length);
        init = true;
        out_size += iv_length;
    }
    
    if(in_size > 0x3ff)
    {
        in_size = 0x3ff;
    }
    
    enc.ProcessData(reinterpret_cast<CryptoPP::byte *>(out + out_size),
        reinterpret_cast<const CryptoPP::byte *>(in), in_size);
    
    out_size += in_size;
}

template<typename Decryption>
void decrypt(Decryption & dec, bool & init, const CryptoPP::SecByteBlock & key, size_t iv_length, const uint8_t * in, size_t & in_size, uint8_t * out, size_t & out_size)
{
    out_size = 0;
    size_t offset = 0;
    if(!init)
    {
        if(in_size < iv_length)
        {
            in_size = 0;
            return;
        }
        
        const CryptoPP::byte * iv = reinterpret_cast<const CryptoPP::byte *>(in);
        dec.SetKeyWithIV(key, key.size(), iv, iv_length);
        init = true;
        offset += iv_length;
    }
    
    dec.ProcessData(reinterpret_cast<CryptoPP::byte *>(out), 
        reinterpret_cast<const CryptoPP::byte *>(in + offset), in_size - offset);
    out_size = in_size - offset;
}

template<typename Encryption>
void encrypt(Encryption & enc, bool & init, const CryptoPP::SecByteBlock & key, CryptoPP::SecByteBlock & iv, const uint8_t * in, size_t & in_size, uint8_t * out, size_t & out_size)
{
    const size_t tag_length = 16;
    const size_t salt_length = key.size();
    
    out_size = 0;
    if(!init)
    {
        CryptoPP::HKDF<CryptoPP::SHA1> hdfa;
        CryptoPP::SecByteBlock skey{key.size()};
        CryptoPP::AutoSeededRandomPool{}.GenerateBlock(reinterpret_cast<CryptoPP::byte *>(out), salt_length);
        hdfa.DeriveKey(skey, key.size(), key.data(), key.size(), 
            reinterpret_cast<const CryptoPP::byte *>(out), 
            salt_length,
            reinterpret_cast<const CryptoPP::byte *>("ss-subkey"), 9);
        enc.SetKeyWithIV(skey, skey.size(), iv, iv.size());
        init = true;
        out_size += salt_length;
    }
    
    if(in_size > 0x3ff)
    {
        in_size = 0x3ff;
    }
    
    std::array<CryptoPP::byte, 2> block_size = 
    {
        static_cast<CryptoPP::byte>((in_size >> 8) & 0xff), 
        static_cast<CryptoPP::byte>(in_size & 0xff), 
    };
    enc.EncryptAndAuthenticate(
        reinterpret_cast<CryptoPP::byte *>(out) + out_size,
        reinterpret_cast<CryptoPP::byte *>(out) + out_size + 2,
        tag_length, iv, iv.size(), nullptr, 0, block_size.data(), 2);
    increase_iv(iv);
    out_size += 2 + tag_length;
    
    enc.EncryptAndAuthenticate(
        reinterpret_cast<CryptoPP::byte *>(out) + out_size,
        reinterpret_cast<CryptoPP::byte *>(out) + out_size + in_size,
        tag_length, iv, iv.size(), nullptr, 0,
        reinterpret_cast<const CryptoPP::byte *>(in),
        in_size);
    increase_iv(iv);
    out_size += in_size + tag_length;
}

void decrypt(CryptoPP::ChaCha20Poly1305::Decryption & dec, bool & init, const CryptoPP::SecByteBlock & key, CryptoPP::SecByteBlock & iv, size_t & size, const uint8_t *in, size_t & in_size, uint8_t * out, size_t & out_size, boost::system::error_code & ec)
{
    const size_t tag_length = 16;
    const size_t salt_length = key.size();
    
    out_size = 0;
    size_t offset = 0;
    if(!init)
    {
        if(in_size < salt_length)
        {
            in_size = 0;
            ec = make_error_code(::shadowsocks::error::cipher_need_more);
            return;
        }
        CryptoPP::HKDF<CryptoPP::SHA1> hdfa;
        CryptoPP::SecByteBlock skey{key.size()};
        hdfa.DeriveKey(skey, key.size(), key.data(), key.size(),
            reinterpret_cast<const CryptoPP::byte *>(in),
            salt_length,
            reinterpret_cast<const CryptoPP::byte *>("ss-subkey"), 9);
        dec.SetKeyWithIV(skey, skey.size(), iv, iv.size());
        init = true;
        offset += salt_length;
    }
    
    for(;;)
    {
        if(size == 0)
        {
            if(in_size - offset < 2 + tag_length)
            {
                ec = make_error_code(::shadowsocks::error::cipher_need_more);
                return;
            }
            
            std::array<CryptoPP::byte, 2> block_size; 
            dec.DecryptAndVerify(block_size.data(), 
                reinterpret_cast<const CryptoPP::byte *>(in) + offset + 2,
                tag_length, iv, iv.size(), nullptr, 0,
                reinterpret_cast<const CryptoPP::byte *>(in) + offset,
                2);
            increase_iv(iv);
            size = (block_size[0] << 8) | block_size[1];
            if(size > 0x03ff)
            {
                ec = make_error_code(::shadowsocks::error::cipher_aead_block_too_long );
                return;
            }
            offset += 2 + tag_length;
        }
        else
        {
            if(in_size - offset < size + tag_length)
            {
                ec = make_error_code(::shadowsocks::error::cipher_need_more);
                return;
            }
            bool result = dec.DecryptAndVerify(
                reinterpret_cast<CryptoPP::byte *>(out),
                reinterpret_cast<const CryptoPP::byte *>(in) + offset + size,
                tag_length, iv, iv.size(), nullptr, 0,
                reinterpret_cast<const CryptoPP::byte *>(in) + offset,
                size);
            
            if(!result)
            {
                ec = make_error_code(::shadowsocks::error::cipher_aead_decrypt_verify_failed);
                return;
            }
            
            offset += size + tag_length;
            out_size += size;
            size = 0;
        }
    }
}

}
}
