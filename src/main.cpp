#include <fstream>

#include <boost/program_options.hpp>
#include <shadowsocks/tcp_listener.h>
#include <shadowsocks/server_session.h>
#include <shadowsocks/client_session.h>

bool parse_command_line(int argc, char * argv[], std::string & configFile)
{
    namespace bp = boost::program_options;
    try
    {
        bp::options_description desc("allowed options");
        desc.add_options()
        ("help,h", "Print help message.")
        ("config,c", bp::value<std::string>(), "The path to config file.");
        
        bp::variables_map vm;
        bp::store(bp::parse_command_line(argc, argv, desc), vm);
        bp::notify(vm);    
        
        if(vm.count("help") || (!vm.count("config")))
        {
            std::cerr << "usage:\n    " << argv[0] << " -c <config_file> \n\n" << desc << std::endl;
            return false;
        }
        
        configFile = vm["config"].as<std::string>();
        std::cout << configFile << std::endl;
        return true;
    }
    catch(const boost::program_options::error & e)
    {
        std::cerr << e.what() << std::endl;
        return false;
    }
}

#ifdef BUILD_SHADOWSOCKS_SERVER
using session_type = shadowsocks::server_session;
std::optional<tcp::endpoint> get_endpoint(const shadowsocks::config & config) {
    std::optional<tcp::endpoint> result;
    result.emplace(asio::ip::make_address(config.server), config.server_port);
    return result;
}
#else
using session_type = shadowsocks::client_session;
std::optional<tcp::endpoint> get_endpoint(const shadowsocks::config & config) {
  std::optional<tcp::endpoint> result;
  if (config.local_address.has_value() && config.local_port.has_value()) {
    result.emplace(asio::ip::make_address(*config.local_address), *config.local_port);
  }
  return result;
}
#endif

int main(int argc, char *argv[])
{
    std::string configFile;
    if(!parse_command_line(argc, argv, configFile))
    {
        return -1;
    }
    
    // locad config
    shadowsocks::config config;
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
    
    config.cipher = shadowsocks::make_cipher_info(config.method);
    if(!config.cipher)
    {
        std::cout << "cipher method not found: [" << config.method << "]." << std::endl;
        return -1;
    }
    config.key = shadowsocks::make_cipher_key(*config.cipher, config.password);
    SPDLOG_INFO("cipher method: {}", config.method);
    
    try 
    {
        asio::io_context context{1};
    
        // start timer to print session num
        asio::spawn(context, [&](asio::yield_context yield) {
          asio::steady_timer timer{context};
          for (error_code ec; !ec;) {
            SPDLOG_INFO("session count: {}", session_type::get_counter());
            timer.expires_from_now(std::chrono::seconds(4));
            timer.async_wait(yield[ec]);
          }
        });

        auto endpoint = get_endpoint(config);
        if(!endpoint.has_value()) {
            spdlog::error("invalid ip or port");
            return -1;
        }

        asio::spawn(context, [&](asio::yield_context yield) {
          shadowsocks::tcp_listener listener{context};
          listener.run(yield, *endpoint, [&](asio::yield_context yield, tcp::socket && socket) {
              auto session = make_shared<session_type>(config, context, std::move(socket));
              session->run(yield);
           });
        });

        size_t workers = config.workers.value_or(1);
        if(workers == 0) {
            workers = 1;
        }
        std::vector<std::thread> threads{workers};
        for(auto & i : threads)
        {
            i = std::thread([&]() {
                context.run();
            });
        }

        for(auto & i : threads) {
            i.join();
        }
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
