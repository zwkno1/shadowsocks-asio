#include <fstream>

#include <tcp_listener.h>
#include <server_session.h>
#include <spdlog/spdlog.h>

int main(int argc, char *argv[])
{
    if(argc < 3 || (std::strcmp(argv[1], "-c") != 0))
    {
        std::cout << "Usage: " << argv[0] << " -c config_file" << std::endl;
        return -1;
    }
    
    shadowsocks::server_config config;
    
    try
    {
        serialization::json_iarchive ia;
        std::fstream f(argv[2], f.in|f.binary);
        std::string content{std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
        ia.load_data(content.data());
        serialization::unserialize(ia, config);
    }
    catch(std::exception & e)
    {
        std::cout << "load config file error: " << e.what() << std::endl;
    }
    
    spdlog::set_level(spdlog::level::from_str(config.log_level));
    
    const shadowsocks::cipher_info * info = shadowsocks::get_cipher_info(config.method);
    if(info == nullptr)
    {
        spdlog::info("cipher method not found: {}, use default: chacha20-ietf-poly1305", config.method);
        config.method = "chacha20-ietf-poly1305";
        info = shadowsocks::get_cipher_info(config.method);
    }
    spdlog::info("cipher method: {}", config.method);
    
    std::vector<uint8_t> key = shadowsocks::get_cipher_key(*info, config.password);
    
    boost::asio::io_context context{1};
    
    // start timer to print session num
    boost::asio::steady_timer timer{context};
    std::function<void()> start_timer;
    start_timer = [&timer, &start_timer]()
    {
        timer.expires_from_now(std::chrono::seconds(15));
        timer.async_wait([&start_timer](boost::system::error_code ec)
        {
            spdlog::debug("session count: {}", shadowsocks::server_session::count());
            if(!ec)
            {
                start_timer();
            }
        });
    };
    start_timer();
    
    shadowsocks::tcp_listener<std::function<void(boost::asio::ip::tcp::socket &&)>> listener(context, [info, &key, &config](boost::asio::ip::tcp::socket && s)
    {
        make_shared<shadowsocks::server_session>(std::move(s), std::make_unique<shadowsocks::cipher_context>(*info, key), config)->start();
    });

    try 
    {
        listener.start(boost::asio::ip::tcp::endpoint{boost::asio::ip::make_address(config.server), config.server_port});
        context.run();
    }
    catch(const CryptoPP::Exception & e)
    {
        spdlog::error("error: {}", e.what());
    }
    catch(boost::system::error_code & ec)
    {
        spdlog::error("{}", ec.message());
    }

    return 0;
}
