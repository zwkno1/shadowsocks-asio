#pragma once

#include <shadowsocks/asio.h>

namespace shadowsocks
{

class tcp_listener : private noncopyable
{
public:
    tcp_listener(asio::io_context & io_context) 
        : io_context_(io_context)
    {
    }

    template<typename Handler>
    void run(asio::yield_context yield, const tcp::endpoint & endpoint, Handler && handler)
    {
        tcp::acceptor acceptor{io_context_};
        acceptor.open(endpoint.protocol());
        acceptor.set_option(tcp::acceptor::reuse_address(true));
        acceptor.bind(endpoint);
        acceptor.listen();
        for (;;) {
            tcp::socket socket{io_context_};
            acceptor.async_accept(socket, yield);
            asio::spawn(io_context_, [&](asio::yield_context yield) {
              handler(yield, std::move(socket));
            });
        }
    }

private:
    asio::io_context & io_context_;
};

} // namespace shadowsocks
