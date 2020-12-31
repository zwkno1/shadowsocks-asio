#pragma once

#include <vector>

#include <shadowsocks/asio.h>
#include <shadowsocks/cipher/stream.h>
#include <shadowsocks/config.h>
#include <shadowsocks/proto.h>
#include <shadowsocks/tunnel.h>
//#include <shadowsocks/detail/counter.h>

namespace shadowsocks
{

class server_session : /*public counter<server_session>,*/ enable_shared_from_this<server_session>
{
	static constexpr size_t BUFFER_SIZE = (MAX_AEAD_BLOCK_SIZE+1)*2;
public:
    server_session(tcp::socket && socket, const config & config)
        : config_(config)
        , local_(std::move(socket), *config.cipher, config.key)
        , remote_(socket.get_executor())
        , active_(chrono::steady_clock::now())
    {
		//++ get_counter();
    }

	~server_session()
	{
		//-- get_counter();
	}

	//static std::atomic<size_t> & get_counter()
	//{
	//    static std::atomic<size_t> counter = 0;
	//	return counter;
	//}

    void run(asio::yield_context yield)
    {
        auto self = shared_from_this();
        if (config_.timeout != 0) {
            asio::spawn(remote_.get_executor(), [self](asio::yield_context yield) {
                try{
                  self->start_timer(yield);
                }catch(system_error &err){
			       SPDLOG_INFO("timer error: {}", err.what());
                }
            });
        }

        asio::spawn(remote_.get_executor(), [self](asio::yield_context yield) {
            try{
                self->start_main(yield);
            }catch(system_error &err){
			    SPDLOG_INFO("main error: {}", err.what());
            }
        });
    }

private:

    void start_timer(asio::yield_context yield)
    {
        asio::steady_timer timer{remote_.get_executor()};
        for (;;) {
          timer.expires_from_now(chrono::seconds(config_.timeout));
          timer.async_wait(yield);
          if (chrono::duration_cast<chrono::seconds>(chrono::steady_clock::now() - active_).count() > config_.timeout) {
            local_.next_layer().shutdown(asio::socket_base::shutdown_both);
            remote_.shutdown(asio::socket_base::shutdown_both);
          }
        }
    }
    
    void start_main(asio::yield_context yield)
    {
        local_.next_layer().set_option(tcp::no_delay{true});
        local_.next_layer().set_option(asio::socket_base::keep_alive{true});
        shadowsocks::request request;
        error_code ec;
        for(;;) {
            size_t nbytes = local_.async_read_some(local_buf_.prepare(BUFFER_SIZE- local_buf_.size()) , yield);
            local_buf_.commit(nbytes);
            if(ec){
              return;
            }
            auto result = request.parse(local_buf_);
            if(result == parse_ok) {
              break;
            }
            if(result != parse_need_more){
              local_.next_layer().shutdown(asio::socket_base::shutdown_both);
                return;
            }
        }

        tcp::endpoint endpoint;
        if(request.type() == DOMAINNAME) {
          tcp::resolver resolver{remote_.get_executor()};
          auto result = resolver.async_resolve(request.domain(), std::to_string(request.port()), yield);
          endpoint = *result.begin();
        }else{
          endpoint = tcp::endpoint{request.address(), request.port()};
        }
        remote_.async_connect(endpoint, yield);

        if (config_.no_delay.value_or(false)) {
          remote_.set_option(tcp::no_delay{true});
        } else {
          local_.next_layer().set_option(tcp::no_delay{false});
        }
        remote_.set_option(asio::socket_base::keep_alive{true});

        tunnel(yield);
    }

    void tunnel(asio::yield_context yield) {
        auto self = shared_from_this();
        tunnel::run(remote_.get_executor(), self, local_, remote_, local_buf_, BUFFER_SIZE);
        tunnel::run(remote_.get_executor(), self, remote_, local_, remote_buf_, BUFFER_SIZE);
    }

    const config & config_;

    stream<tcp::socket> local_;

    tcp::socket remote_;

    asio::streambuf local_buf_;

    asio::streambuf remote_buf_;

    chrono::steady_clock::time_point active_;
};

}
