#pragma once

#include <shadowsocks/asio.h>

namespace shadowsocks
{
    
class udp_server : public enable_shared_from_this<udp_server>
{
public:
    udp_server(asio::io_context & ctx)
        : socket_(ctx)
    {
    }
    
    void do_recv()
    {
        socket_.async_receive_from(asio::buffer(buf_.data(), buf_.size()), endpoint_, [self = shared_from_this()](error_code ec, size_t bytes)
        {
            
        });
    }

private:
    std::array<uint8_t, 1024> buf_;
    udp::socket socket_;    
    udp::endpoint endpoint_;
};

}
