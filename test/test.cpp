
#include <cryptopp/files.h>
#include <cryptopp/hex.h>
#include <cryptopp/modes.h>

#include <shadowsocks/stream/detail/cipher_ops.h>
#include <shadowsocks/stream/stream.h>

using namespace CryptoPP;

void test_cfb()
{
    AutoSeededRandomPool prng;

    shadowsocks::detail::cipher_pair_variant v;
    shadowsocks::detail::make_cipher_pair(shadowsocks::AES_CFB, v);
    SecByteBlock key(24);
    prng.GenerateBlock( key, key.size() );

    byte iv[ AES::BLOCKSIZE ];
    prng.GenerateBlock( iv, sizeof(iv) );
    std::cout << AES::DEFAULT_KEYLENGTH << "," << AES::BLOCKSIZE << std::endl;

    std::string plain = "CFB Mode Test";
    std::string cipher, encoded, recovered;
    
    std::visit([&](auto && arg)
    {
        try
        {
            std::cout << "plain text: " << plain << std::endl;
            
            arg.encryption.SetKeyWithIV( key, key.size(), iv, sizeof(iv));
            
            // CFB mode must not use padding. Specifying
            //  a scheme will result in an exception
            StringSource ss1( plain, true, 
                              new StreamTransformationFilter( arg.encryption,                                                           new StringSink( cipher )
                              ) // StreamTransformationFilter      
            ); // StringSource
        }
        catch( CryptoPP::Exception& e )
        {
            std::cerr << e.what() << std::endl;
            exit(1);
        }
    }, v);
    
    // Pretty print cipher text
    StringSource ss2( cipher, true,
                      new HexEncoder(
                          new StringSink( encoded )
                      ) // HexEncoder
    ); // StringSource
    std::cout << "cipher text: " << encoded << std::endl;

    try
    {
        CFB_Mode< AES >::Decryption dec;
        dec.SetKeyWithIV( key, key.size(), iv, sizeof(iv));
        
        // The StreamTransformationFilter removes
        //  padding as required.
        StringSource ss3( cipher, true, 
                          new StreamTransformationFilter( dec,
                                                          new StringSink( recovered )
                          ) // StreamTransformationFilter
        ); // StringSource
        
        std::cout << "recovered text: " << recovered << std::endl;
    }
    catch( CryptoPP::Exception& e )
    {
        std::cerr << e.what() << std::endl;
        exit(1);
    }
}

int main(int argc, char* argv[])
{
    test_cfb();

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
    size_t enc_in_size = sizeof(pt);
    size_t enc_out_size = 0;
    shadowsocks::detail::encrypt_aead(enc, enc_init, key, enc_iv, pt, enc_in_size, enc_buf, enc_out_size);
    
    std::cout << "Plain: ";
    StringSource(pt, sizeof(pt), true, new HexEncoder(new FileSink(std::cout)));
    std::cout << "\n" << std::endl;

    std::cout << "Cipher: ";
    StringSource(enc_buf, enc_out_size, true, new HexEncoder(new FileSink(std::cout)));
    std::cout << std::endl;
    
    std::cout << "plain size:" << sizeof(pt) << std::endl;
    std::cout << "encrypt size:" << enc_out_size << ", left: " << sizeof(pt) - enc_in_size << std::endl;

    //std::cout << "MAC: ";
    //StringSource(mac, sizeof(mac), true, new HexEncoder(new FileSink(std::cout)));
    //std::cout << "\n" << std::endl;

    bool dec_init = false;
    size_t block_size = 0;
    ChaCha20Poly1305::Decryption dec;
    CryptoPP::SecByteBlock dec_iv(iv_arr, sizeof(iv_arr));
    byte dec_buf[10240];
    size_t dec_in_size = enc_out_size;
    size_t dec_out_size = 0;
    
    boost::system::error_code ec;
    shadowsocks::detail::decrypt_aead(dec, dec_init, key, dec_iv, block_size, enc_buf, dec_in_size, dec_buf, dec_out_size, ec);
    std::cout << "decryt result: " << ec.message() << std::endl;
    std::cout << "decrypt size:" << dec_out_size << ", left: " << enc_out_size - dec_in_size << std::endl;

    std::cout << "Recover: ";
    StringSource(dec_buf, dec_out_size, true, new HexEncoder(new FileSink(std::cout)));
    std::cout << "\n" << std::endl;

    return 0;
}
