#include <tcp_listener.h>
#include <server_session.h>
#include <client_session.h>


//#include <botan/md5.h>
//
//std::vector<uint8_t> evpBytesTokey(const std::string & password)
//{
//    std::vector<uint8_t> key;
//    key.resize(32);
//    Botan::MD5 md5;
//    md5.update(reinterpret_cast<const uint8_t * >(password.data()) , password.size());
//    md5.final(key.data());
//    md5.update(key.data(), 16);
//    md5.update(reinterpret_cast<const uint8_t * >(password.data()) , password.size());
//    md5.final(key.data()+16);
//    return key;
//}

int main(int argc, char *argv[])
{
    boost::asio::io_context context;

    std::string algo = "ChaCha(20)";
    std::vector<uint8_t> key;// = evpBytesTokey("123456");

    shadowsocks::tcp_listener<std::function<void(boost::asio::ip::tcp::socket &&)>> listener(context, [&algo, &key](boost::asio::ip::tcp::socket && s)
    {
          std::cout << "session count: " << shadowsocks::server_session::count() << std::endl;
          make_shared<shadowsocks::server_session>(std::move(s), shadowsocks::cipher_context{algo, key, 8})->start();
    });

    listener.start(boost::asio::ip::tcp::endpoint{boost::asio::ip::make_address("0.0.0.0"), 33333});

    context.run();


    return 0;
}
