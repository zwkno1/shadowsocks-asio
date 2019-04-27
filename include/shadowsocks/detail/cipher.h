#pragma once

#include <boost/asio/buffer.hpp>

#include <cryptopp/cryptlib.h>
#include <cryptopp/secblock.h>
#include <cryptopp/osrng.h>
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
#include <cryptopp/hkdf.h>
#include <cryptopp/sha.h>
#include <cryptopp/chachapoly.h>

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
void encryt(Encryption & enc, bool & init, const CryptoPP::SecByteBlock & key, size_t iv_length, boost::asio::const_buffer & in, boost::asio::mutable_buffer & out)
{
    if(!init)
    {
        CryptoPP::byte * iv = reinterpret_cast<CryptoPP::byte *>(out.data());
        CryptoPP::AutoSeededRandomPool{}.GenerateBlock(iv, iv_length);
        enc.SetKeyWithIV(key, key.size(), iv, iv_length);
        out += iv_length;
        init = true;
    }
    
    enc.ProcessData(reinterpret_cast<CryptoPP::byte *>(out.data()), reinterpret_cast<const CryptoPP::byte *>(in.data()), in.size());
    out += in.size();
    in += in.size();
}

template<typename Decryption>
void decryt(Decryption & dec, bool & init, const CryptoPP::SecByteBlock & key, size_t iv_length, boost::asio::const_buffer & in, boost::asio::mutable_buffer & out)
{
    if(!init)
    {
        if(in.size() < iv_length)
            return;
        
        const CryptoPP::byte * iv = reinterpret_cast<const CryptoPP::byte *>(in.data());
        dec.SetKeyWithIV(key, key.size(), iv, iv_length);
        in += iv_length;
        init = true;
    }
    
    dec.ProcessData(reinterpret_cast<CryptoPP::byte *>(out.data()), reinterpret_cast<const CryptoPP::byte *>(in.data()), in.size());
    out += in.size();
    in += in.size();
}

template<typename Encryption>
void encryt(Encryption & enc, bool & init, const CryptoPP::SecByteBlock & key, CryptoPP::SecByteBlock & iv, boost::asio::const_buffer & in, boost::asio::mutable_buffer & out)
{
    const size_t tag_length = 16;
    const size_t salt_length = key.size();
    
    if(!init)
    {
        CryptoPP::HKDF<CryptoPP::SHA1> hdfa;
        CryptoPP::SecByteBlock skey{key.size()};
        CryptoPP::AutoSeededRandomPool{}.GenerateBlock(reinterpret_cast<CryptoPP::byte *>(out.data()), salt_length);
        hdfa.DeriveKey(skey, key.size(), key.data(), key.size(), 
            reinterpret_cast<CryptoPP::byte *>(out.data()), 
            salt_length,
            reinterpret_cast<const CryptoPP::byte *>("ss-subkey"), 9);
        enc.SetKeyWithIV(skey, skey.size(), iv, iv.size());
        init = true;
        out += salt_length;
    }
    
    std::array<CryptoPP::byte, 2> block_size = 
    {
        static_cast<CryptoPP::byte>((in.size() >> 8) & 0xff), 
        static_cast<CryptoPP::byte>(in.size() & 0xff), 
    };
    enc.EncryptAndAuthenticate(
        reinterpret_cast<CryptoPP::byte *>(out.data()),
        reinterpret_cast<CryptoPP::byte *>(out.data()) + 2,
        tag_length, iv, iv.size(), nullptr, 0, block_size.data(), 2);
    out += 2 + tag_length;
    increase_iv(iv);
    
    enc.EncryptAndAuthenticate(
        reinterpret_cast<CryptoPP::byte *>(out.data()),
        reinterpret_cast<CryptoPP::byte *>(out.data()) + in.size(),
        tag_length, iv, iv.size(), nullptr, 0,
        reinterpret_cast<const CryptoPP::byte *>(in.data()),
        in.size());
    out += in.size() + tag_length ;
    increase_iv(iv);
}

bool decryt(CryptoPP::ChaCha20Poly1305::Decryption & dec, bool & init, const CryptoPP::SecByteBlock & key, CryptoPP::SecByteBlock & iv, size_t & size, boost::asio::const_buffer & in, boost::asio::mutable_buffer & out)
{
    const size_t tag_length = 16;
    const size_t salt_length = key.size();
    
    if(!init)
    {
        if(in.size() < salt_length)
            return true;
        CryptoPP::HKDF<CryptoPP::SHA1> hdfa;
        CryptoPP::SecByteBlock skey{key.size()};
        hdfa.DeriveKey(skey, key.size(), key.data(), key.size(),
            reinterpret_cast<const CryptoPP::byte *>(in.data()),
            salt_length,
            reinterpret_cast<const CryptoPP::byte *>("ss-subkey"), 9);
        dec.SetKeyWithIV(skey, skey.size(), iv, iv.size());
        in += salt_length;
        init = true;
    }
    
    for(;;)
    {
        if(size == 0)
        {
            if(in.size() < 2 + tag_length)
                return true;
            
            std::array<CryptoPP::byte, 2> block_size; 
            dec.DecryptAndVerify(block_size.data(), 
                reinterpret_cast<const CryptoPP::byte *>(in.data()) + 2,
                tag_length, iv, iv.size(), nullptr, 0,
                reinterpret_cast<const CryptoPP::byte *>(in.data()),
                2);
            increase_iv(iv);
            size = (block_size[0] << 8) | block_size[1];
            if(size > 0x03ff)
                return false;
            in += 2 + tag_length;
        }
        else
        {
            if(in.size() < size + tag_length)
                return true;
            bool result = dec.DecryptAndVerify(
                reinterpret_cast<CryptoPP::byte *>(out.data()),
                reinterpret_cast<const CryptoPP::byte *>(in.data()) + size,
                tag_length, iv, iv.size(), nullptr, 0,
                reinterpret_cast<const CryptoPP::byte *>(in.data()),
                size);
            
            if(!result)
                return false;
            
            in += size + tag_length;
            out += size;
            size = 0;
        }
    }
}

}
}
