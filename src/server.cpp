#include <tcp_listener.h>
#include <server_session.h>
#include <spdlog/spdlog.h>
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/md5.h>

namespace shadowsocks
{
    
const std::unordered_map<std::string, cipher_info> cipher_infos = 
{
    {"aes-128-cfb", {AES_CFB, 16, 16, STREAM}},
    {"aes-192-cfb", {AES_CFB, 24, 16, STREAM}},
    {"aes-256-cfb", {AES_CFB, 32, 16, STREAM}},
    {"aes-128-ctr", {AES_CTR_BE, 16, 16, STREAM}},
    {"aes-192-ctr", {AES_CTR_BE, 24, 16, STREAM}},
    {"aes-256-ctr", {AES_CTR_BE, 32, 16, STREAM}},
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
    {"chacha20-ietf-poly1305", {CHACHA20_POLY1305, 32, 12, AEAD, 32, 16}},
    {"aes-128-gcm", {AES_GCM, 16, 12, AEAD, 16, 16}},
    {"aes-192-gcm", {AES_GCM, 24, 12, AEAD, 24, 16}},
    {"aes-256-gcm", {AES_GCM, 32, 12, AEAD, 32, 16}}
};
    
}

std::vector<uint8_t> evpBytesToKey(const shadowsocks::cipher_info & info, const std::string &password)
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

int main(int argc, char *argv[])
{
    spdlog::set_pattern("[%l] %v");
    spdlog::set_level(spdlog::level::debug);
    spdlog::debug(" aes keylen: {}, ivlen: {} ", CryptoPP::AES::DEFAULT_KEYLENGTH, CryptoPP::AES::BLOCKSIZE);
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
    spdlog::info("cipher: {}, key len: {}, iv len: {}", (argc > 1 ? argv[1] : "chacha20"), info->key_length_, info->iv_length_);

    shadowsocks::tcp_listener<std::function<void(boost::asio::ip::tcp::socket &&)>> listener(context, [info, &key](boost::asio::ip::tcp::socket && s)
    {
        spdlog::debug("session count: {}", shadowsocks::server_session::count());
        make_shared<shadowsocks::server_session>(std::move(s), std::make_unique<shadowsocks::cipher_context>(*info, key))->start();
    });

    listener.start(boost::asio::ip::tcp::endpoint{boost::asio::ip::make_address("0.0.0.0"), 33333});

    try 
    {
        context.run();
    }
    catch(const CryptoPP::Exception & e)
    {
        spdlog::debug("error: {}", e.what());
    }

    return 0;
}
