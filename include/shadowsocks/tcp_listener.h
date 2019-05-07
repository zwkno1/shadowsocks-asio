#pragma once

#include <shadowsocks/asio.h>

namespace shadowsocks
{

template <typename Handler>
class tcp_listener : private noncopyable
{
public:
    explicit tcp_listener(asio::io_context & io_context, Handler h)
        : io_context_(io_context)
        , acceptor_(io_context)
        , socket_(io_context)
        , handler_(std::move(h))
    {
    }

    void start(const tcp::endpoint & endpoint)
    {
        // Open the acceptor with the option to reuse the address (i.e. SO_REUSEADDR).
        acceptor_.open(endpoint.protocol());
        acceptor_.set_option(tcp::acceptor::reuse_address(true));
        acceptor_.bind(endpoint);
        acceptor_.listen();
        do_accept();
    }

    void stop()
    {
        acceptor_.close();
    }

    asio::io_context & get_io_context()
    {
        return io_context_;
    }

private:
    void do_accept()
    {
        acceptor_.async_accept(socket_, [this] (error_code ec)
        {
            if(!ec)
            {
                handler_(std::move(socket_));
                do_accept();
            }
        });
    }

    asio::io_context & io_context_;

    tcp::endpoint endpoint_;

    /// Acceptor used to listen for incoming connections.
    tcp::acceptor acceptor_;

    tcp::socket socket_;

    Handler handler_;
};

}
