#pragma once

#include <shadowsocks/asio.h>
#include <shadowsocks/cipher/stream.h>
#include <shadowsocks/config.h>
#include <shadowsocks/proto.h>
#include <shadowsocks/tunnel.h>
#include <shadowsocks/detail/counter.h>

namespace shadowsocks
{

class server_session : public counter<server_session>, public enable_shared_from_this<server_session>
{
	static constexpr size_t BUFFER_SIZE = (MAX_AEAD_BLOCK_SIZE+1)*2;
public:
    server_session(const config & config, asio::io_context & io_context, tcp::socket && socket)
        : config_(config)
        , io_context_(io_context)
        , local_(std::move(socket), *config.cipher, config.key)
        , remote_(socket.get_executor())
        , timer_(socket.get_executor())
        , active_(chrono::steady_clock::now())
    {
    }

    void run(asio::yield_context yield)
    {
        auto self = shared_from_this();
        if (config_.timeout != 0) {
            asio::spawn(io_context_, [self](asio::yield_context yield) {
                try{
                  self->run_timer(yield);
                }catch(system_error &err){
			       SPDLOG_DEBUG("timer error: {}", err.what());
                }
				self->stop();
            });
        }

        asio::spawn(io_context_, [self](asio::yield_context yield) {
            try{
                self->run_main(yield);
            }catch(system_error &err){
			    SPDLOG_DEBUG("main error: {}", err.what());
            }
			self->stop();
        });
    }

private:
	void stop() {
		error_code ec;
		local_.next_layer().shutdown(asio::socket_base::shutdown_both, ec);
		remote_.shutdown(asio::socket_base::shutdown_both, ec);
		timer_.cancel(ec);
	}

    void run_timer(asio::yield_context yield)
    {
        for (;;) {
          timer_.expires_from_now(chrono::seconds(config_.timeout));
          timer_.async_wait(yield);
          if (chrono::duration_cast<chrono::seconds>(chrono::steady_clock::now() - active_).count() > config_.timeout) {
			break;
          }
        }
    }
    
    void run_main(asio::yield_context yield)
    {
        local_.next_layer().set_option(tcp::no_delay{true});
        local_.next_layer().set_option(asio::socket_base::keep_alive{true});
        shadowsocks::request request;
        for(;;) {
            size_t nbytes = local_.async_read_some(local_buf_.prepare(BUFFER_SIZE- local_buf_.size()) , yield);
            local_buf_.commit(nbytes);
            auto result = request.parse(local_buf_);
            if(result == parse_ok) {
              break;
            }
			if(result != parse_need_more) {
                return;
            }
        }

        tcp::endpoint endpoint;
        if(request.type() == DOMAINNAME) {
          tcp::resolver resolver{io_context_};
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
        asio::spawn(io_context_, [self](asio::yield_context yield) {
			try{
			    tunnel::run(yield, self->remote_, self->local_, self->remote_buf_, BUFFER_SIZE, 
				    [&](size_t){ self->active_ = chrono::steady_clock::now(); }, [](size_t){});
            }catch(system_error &err){
			    SPDLOG_DEBUG("tunnel error: {}", err.what());
			}
			self->stop();
		});

        tunnel::run(yield, local_, remote_, local_buf_, BUFFER_SIZE, 
		    [&](size_t){ self->active_ = chrono::steady_clock::now(); }, [](size_t){});
    }

    const config & config_;

    asio::io_context & io_context_;

    stream<tcp::socket> local_;

    tcp::socket remote_;

    asio::streambuf local_buf_;

    asio::streambuf remote_buf_;

    asio::steady_timer timer_;

    chrono::steady_clock::time_point active_;
};

} // namespace shadowsocks
