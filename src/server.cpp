#include <tcp_listener.h>
#include <server_session.h>
#include <client_session.h>
#include <unordered_map>


#include <botan/md5.h>
#include <botan/lookup.h>
#include <botan/filter.h>
#include <botan/key_filt.h>



namespace shadowsocks
{
    
const std::unordered_map<std::string, cipher_info> cipher_infos =
{
    {"aes-128-cfb", {"AES-128/CFB", 16, 16, cipher_type::STREAM}},
    {"aes-192-cfb", {"AES-192/CFB", 24, 16, cipher_type::STREAM}},
    {"aes-256-cfb", {"AES-256/CFB", 32, 16, cipher_type::STREAM}},
    {"aes-128-ctr", {"AES-128/CTR-BE", 16, 16, cipher_type::STREAM}},
    {"aes-192-ctr", {"AES-192/CTR-BE", 24, 16, cipher_type::STREAM}},
    {"aes-256-ctr", {"AES-256/CTR-BE", 32, 16, cipher_type::STREAM}},
    {"bf-cfb", {"Blowfish/CFB", 16, 8, cipher_type::STREAM}},
    {"camellia-128-cfb", {"Camellia-128/CFB", 16, 16, cipher_type::STREAM}},
    {"camellia-192-cfb", {"Camellia-192/CFB", 24, 16, cipher_type::STREAM}},
    {"camellia-256-cfb", {"Camellia-256/CFB", 32, 16, cipher_type::STREAM}},
    {"cast5-cfb", {"CAST-128/CFB", 16, 8, cipher_type::STREAM}},
    {"chacha20", {"ChaCha", 32, 8, cipher_type::STREAM}},
    {"chacha20-ietf", {"ChaCha", 32, 12, cipher_type::STREAM}},
    {"des-cfb", {"DES/CFB", 8, 8, cipher_type::STREAM}},
    {"idea-cfb", {"IDEA/CFB", 16, 8, cipher_type::STREAM}},
    // RC2 is not supported by botan-2
    //{"rc2-cfb", {"RC2/CFB", 16, 8, cipher_type::STREAM}},
    {"rc4-md5", {"RC4-MD5", 16, 16, cipher_type::STREAM}},
    {"salsa20", {"Salsa20", 32, 8, cipher_type::STREAM}},
    {"seed-cfb", {"SEED/CFB", 16, 16, cipher_type::STREAM}},
    {"serpent-256-cfb", {"Serpent/CFB", 32, 16, cipher_type::STREAM}}
    ,{"chacha20-ietf-poly1305", {"ChaCha20Poly1305", 32, 12, cipher_type::AEAD, 32, 16}},
    {"aes-128-gcm", {"AES-128/GCM", 16, 12, cipher_type::AEAD, 16, 16}},
    {"aes-192-gcm", {"AES-192/GCM", 24, 12, cipher_type::AEAD, 24, 16}},
    {"aes-256-gcm", {"AES-256/GCM", 32, 12, cipher_type::AEAD, 32, 16}}
};

}

const std::string kdfLabel = {"ss-subkey"};

std::vector<uint8_t> evpBytesToKey(const shadowsocks::cipher_info & info, const std::string &password)
{
    std::vector<uint8_t> result;
    for(int i = 0; result.size() < info.key_length; ++i)
    {
        Botan::MD5 md5;
        if (i != 0)
        {
            md5.update(&result[(i-1)*16], 16);
        }
        md5.update(reinterpret_cast<const uint8_t * >(password.data()), password.size());
        result.resize((i+1)*16);
        md5.final(&result[i*16]);
    }
    
    result.resize(info.key_length);
    return result;
}

int main(int argc, char *argv[])
{
    boost::asio::io_context context;
    
    const shadowsocks::cipher_info * info = &shadowsocks::cipher_infos.find("chacha20")->second;
    if(argc > 1)
    {
        auto iter = shadowsocks::cipher_infos.find(argv[1]);
        if(iter != shadowsocks::cipher_infos.end())
        {
            info = &iter->second;
        }
    }
    std::vector<uint8_t> key = evpBytesToKey(*info, "123456");
    //Botan::get_cipher(info->name, Botan::SymmetricKey{}, Botan::InitializationVector{}, Botan::ENCRYPTION);
    
    shadowsocks::tcp_listener<std::function<void(boost::asio::ip::tcp::socket &&)>> listener(context, [&info, &key](boost::asio::ip::tcp::socket && s)
    {
        std::cout << "session count: " << shadowsocks::server_session::count() << std::endl;
        make_shared<shadowsocks::server_session>(std::move(s), shadowsocks::cipher_context{*info, key})->start();
    });
    
    listener.start(boost::asio::ip::tcp::endpoint{boost::asio::ip::make_address("0.0.0.0"), 33333});
    
    try
    {
        context.run();
    }
    catch(boost::system::error_code ec)
    {
        std::cout << ec.message() << std::endl;
    }
    
    return 0;
}
