
#include <boost/asio.hpp>

#include <cryptopp/cryptlib.h>
#include <cryptopp/secblock.h>
#include <cryptopp/chacha.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>
#include <cryptopp/hex.h>
#include <cryptopp/modes.h>
#include <cryptopp/aes.h>
#include <cryptopp/blowfish.h>
#include <cryptopp/camellia.h>
#include <cryptopp/chachapoly.h>
#include <cryptopp/hkdf.h>
#include <cryptopp/sha.h>

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

void encryt(CryptoPP::ChaCha20Poly1305::Encryption & enc, bool & init, const CryptoPP::SecByteBlock & key, CryptoPP::SecByteBlock & iv, boost::asio::const_buffer & in, boost::asio::mutable_buffer & out)
{
    const size_t tag_length = 16;
    const size_t salt_length = key.size();
    
    if(!init)
    {
        CryptoPP::HKDF<CryptoPP::SHA1> hdfa;
        CryptoPP::SecByteBlock skey{key.size()};
        CryptoPP::SecByteBlock salt{salt_length};
        CryptoPP::AutoSeededRandomPool{}.GenerateBlock(salt, salt.size());
        hdfa.DeriveKey(skey, key.size(), key.data(), key.size(), salt, salt.size(),
            reinterpret_cast<const CryptoPP::byte *>("ss-subkey"), 9);
        enc.SetKeyWithIV(skey, skey.size(), iv, iv.size());
        init = true;
        out += salt.size();
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

int main(int argc, char* argv[])
{
    using namespace CryptoPP;

    const byte pt[] = {
        0x4c,0x61,0x64,0x69,0x65,0x73,0x20,0x61,0x6e,0x64,0x20,0x47,0x65,0x6e,0x74,0x6c,
        0x65,0x6d,0x65,0x6e,0x20,0x6f,0x66,0x20,0x74,0x68,0x65,0x20,0x63,0x6c,0x61,0x73,
        0x73,0x20,0x6f,0x66,0x20,0x27,0x39,0x39,0x3a,0x20,0x49,0x66,0x20,0x49,0x20,0x63,
        0x6f,0x75,0x6c,0x64,0x20,0x6f,0x66,0x66,0x65,0x72,0x20,0x79,0x6f,0x75,0x20,0x6f,
        0x6e,0x6c,0x79,0x20,0x6f,0x6e,0x65,0x20,0x74,0x69,0x70,0x20,0x66,0x6f,0x72,0x20,
        0x74,0x68,0x65,0x20,0x66,0x75,0x74,0x75,0x72,0x65,0x2c,0x20,0x73,0x75,0x6e,0x73,
        0x63,0x72,0x65,0x65,0x6e,0x20,0x77,0x6f,0x75,0x6c,0x64,0x20,0x62,0x65,0x20,0x69,
        0x74,0x2e
    };

    const byte aad[] = {
        0x50,0x51,0x52,0x53,0xc0,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7
        // 0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,0x88,0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f,
        // 0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,0x98,0x99,0x9a,0x9b,0x9c,0x9d,0x9e,0x9f
    };

    CryptoPP::byte key_arr[] = 
    {
        0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,0x88,0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f,
        0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,0x98,0x99,0x9a,0x9b,0x9c,0x9d,0x9e,0x9f
    };

    CryptoPP::byte iv_arr[] = 
    {
        0x00,0x00,0x00,0x00,                      // Common
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00   // IV
    };

    CryptoPP::SecByteBlock key{key_arr, sizeof(key_arr)};
    CryptoPP::SecByteBlock enc_iv(iv_arr, sizeof(iv_arr));
    byte enc_buf[10240];

    bool enc_init = false;
    ChaCha20Poly1305::Encryption enc;
    boost::asio::const_buffer in(pt, sizeof(pt));
    boost::asio::mutable_buffer out(enc_buf, sizeof( enc_buf ));
    encryt(enc, enc_init, key, enc_iv, in, out);
    size_t enc_size = sizeof(enc_buf) - out.size();
    
    std::cout << "Plain: ";
    StringSource(pt, sizeof(pt), true, new HexEncoder(new FileSink(std::cout)));
    std::cout << "\n" << std::endl;

    std::cout << "Cipher: ";
    StringSource( enc_buf, sizeof( enc_buf ) - out.size(), true, new HexEncoder(new FileSink(std::cout)));
    std::cout << std::endl;

    //std::cout << "MAC: ";
    //StringSource(mac, sizeof(mac), true, new HexEncoder(new FileSink(std::cout)));
    //std::cout << "\n" << std::endl;

    bool dec_init = false;
    size_t block_size = 0;
    ChaCha20Poly1305::Decryption dec;
    CryptoPP::SecByteBlock dec_iv(iv_arr, sizeof(iv_arr));
    byte dec_buf[10240];
    boost::asio::const_buffer dec_in(enc_buf, enc_size);
    boost::asio::mutable_buffer dec_out(dec_buf, sizeof(dec_buf));
    
    bool ret = decryt(dec, dec_init, key, dec_iv, block_size, dec_in, dec_out);
    size_t dec_size = sizeof(dec_buf) - dec_out.size();
    std::cout << ret << std::endl;

    std::cout << "Recover: ";
    StringSource(dec_buf, dec_size, true, new HexEncoder(new FileSink(std::cout)));
    std::cout << "\n" << std::endl;

    return 0;
}
