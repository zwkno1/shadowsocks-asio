#pragma once

#include <vector>

#include <shadowsocks/asio.h>
#include <shadowsocks/cipher/stream.h>
#include <shadowsocks/ss_config.h>
#include <shadowsocks/proto.h>
#include <shadowsocks/tunnel.h>

namespace shadowsocks
{

class server_session : public enable_shared_from_this<server_session>
{
public:
    server_session(tcp::socket && socket, const ss_config & config)
        : io_context_(socket.get_io_context())
        , config_(config)
        , local_(std::move(socket), *config.cipher, config.key)
        , remote_(socket.get_io_context())
        , active_(chrono::steady_clock::now())
    {
    }

    void run(asio::yield_context yield)
    {
        auto self = shared_from_this();
        if (config_.timeout != 0) {
            asio::spawn(io_context_, [self](asio::yield_context yield) {
                try{
                  self->start_timer(yield);
                }catch(system_error &err){
                }
            });
        }

        asio::spawn(io_context_, [self](asio::yield_context yield) {
            try{
                self->start_main(yield);
            }catch(system_error &err){
            }
        });
    }

private:

    void start_timer(asio::yield_context yield)
    {
        asio::steady_timer timer{io_context_};
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
            size_t nbytes = local_.async_read_some(local_buf_.prepare(32768 - local_buf_.size()) , yield);
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
        tunnel::run(io_context_, self, local_, remote_, local_buf_, 32768);
        tunnel::run(io_context_, self, remote_, local_, remote_buf_, 32768);
    }

    
    asio::io_context & io_context_;

    const ss_config & config_;

    stream<tcp::socket> local_;

    tcp::socket remote_;

    asio::streambuf local_buf_;

    asio::streambuf remote_buf_;

    chrono::steady_clock::time_point active_;
};

}
