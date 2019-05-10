#include <fstream>

#include <boost/program_options.hpp>

#include <shadowsocks/tcp_listener.h>
#include <shadowsocks/server_session.h>
#include <shadowsocks/client_session.h>
#include <spdlog/spdlog.h>
#include <shadowsocks/udp_server.h>

bool parse_command_line(int argc, char * argv[], std::string & configFile)
{
    namespace bp = boost::program_options;
    try
    {
        bp::options_description desc("allowed options");
        desc.add_options()
        ("help,h", "Print help message.")
        ("config,c", bp::value<std::string>()->value_name("<config_file>"), "The path to config file.");
        
        bp::variables_map vm;
        bp::store(bp::parse_command_line(argc, argv, desc), vm);
        bp::notify(vm);    
        
        if(vm.count("help") || (!vm.count("config")))
        {
            std::cerr << "usage:\n    " << argv[0] << " \n\n" << desc << std::endl;
            return false;
        }
        
        configFile = vm["config"].as<std::string>();
        
        return true;
    }
    catch(std::exception & e)
    {
        std::cerr << e.what() << std::endl;
        return false;
    }
}

int main(int argc, char *argv[])
{
    std::string configFile;
    if(!parse_command_line(argc, argv, configFile))
    {
        return -1;
    }
    
    // locad config
    shadowsocks::ss_config config;
    try
    {
        serialization::json_iarchive ia;
        std::fstream f(configFile, f.in|f.binary);
        std::string content{std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
        ia.load_data(content.data());
        serialization::unserialize(ia, config);
    }
    catch(std::exception & e)
    {
        std::cout << "load config file error: " << e.what() << std::endl;
        return -1;
    }
    
    spdlog::set_level(spdlog::level::from_str(config.log_level.value_or("info")));
    
    config.cipher = shadowsocks::get_cipher_info(config.method);
    if(!config.cipher)
    {
        std::cout << "cipher method not found: [" << config.method << "]." << std::endl;
        return -1;
    }
    config.key = shadowsocks::build_cipher_key(*config.cipher, config.password);
    spdlog::info("cipher method: {}", config.method);
    
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
    
    shadowsocks::tcp_listener<std::function<void(boost::asio::ip::tcp::socket &&)>> listener(context, [&config](boost::asio::ip::tcp::socket && s)
    {
#ifdef BUILD_SHADOWSOCKS_SERVER
        make_shared<shadowsocks::server_session>(std::move(s), config)->start();
#else
        make_shared<shadowsocks::client_session>(std::move(s), config)->start();
#endif
    });

    try 
    {
#ifdef BUILD_SHADOWSOCKS_SERVER
        listener.start(boost::asio::ip::tcp::endpoint{boost::asio::ip::make_address(config.server_address), config.server_port});
#else
        if((!config.local_address) || (!config.local_port))
        {
            std::cout << "ss-local should configure local_address and local_port" << std::endl;
            return -1;
        }
        listener.start(boost::asio::ip::tcp::endpoint{boost::asio::ip::make_address(*config.local_address), *config.local_port});
#endif
        context.run();
    }
    catch(const CryptoPP::Exception & e)
    {
        spdlog::error("cipher error: {}", e.what());
    }
    catch(boost::system::error_code & ec)
    {
        spdlog::error("{}", ec.message());
    }

    return 0;
}
