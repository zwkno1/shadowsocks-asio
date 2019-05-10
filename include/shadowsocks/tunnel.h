#pragma once

#include <spdlog/spdlog.h>

#include <shadowsocks/asio.h>

namespace shadowsocks
{

template <typename Stream1, typename Stream2, typename Buffer, typename Handler>
class tunnel : public enable_shared_from_this<tunnel<Stream1, Stream2, Buffer, Handler>>
{
public:
    tunnel(Stream1 & s1, Stream2 & s2, Buffer & buf1, Buffer & buf2, Handler h)
        : s1_(s1)
        , s2_(s2)
        , buf1_(buf1)
        , buf2_(buf2)
        , handler_(std::forward<Handler>(h))
    {
        error_code ignored_ec;
        if constexpr(std::is_same<tcp::socket, std::decay_t<decltype(s2)>>::value)
        {
            auto const & ep1 = s1_.next_layer().remote_endpoint(ignored_ec);
            auto const & ep2 = s2_.local_endpoint(ignored_ec);
            ep1_ = ep1.address().to_string() + ":" + std::to_string(ep1.port());
            ep2_ = ep2.address().to_string() + ":" + std::to_string(ep2.port());
        }
        else
        {
            auto const & ep1 = s1_.remote_endpoint(ignored_ec);
            auto const & ep2 = s2_.next_layer().local_endpoint(ignored_ec);
            ep1_ = ep1.address().to_string() + ":" + std::to_string(ep1.port());
            ep2_ = ep2.address().to_string() + ":" + std::to_string(ep2.port());
        }
    }

    void start(size_t buf1_size = 0, size_t buf2_size = 0)
    {
        if(buf1_size == 0)
        {
            handle_write_s2(error_code{}, 0);
        }
        else
        {
            handle_read_s1(error_code{}, buf1_size);
        }

        if(buf2_size == 0)
        {
            handle_write_s1(error_code{}, 0);
        }
        else
        {
            handle_read_s2(error_code{}, buf2_size);
        }
    }

    void handle_read_s1(error_code ec, size_t bytes)
    {
        spdlog::debug("[ {} -> {} ] (ec: {} , bytes: {})", ep1_, ep2_, ec.message(), bytes);
        if(ec)
        {
            return;
        }
        
        handler_();

        asio::async_write(s2_, asio::buffer(buf1_.data(), bytes), [this, self = this->shared_from_this()](error_code ec, size_t bytes)
        {
            handle_write_s2(ec, bytes);
        });
    }

    void handle_write_s2(error_code ec, size_t bytes)
    {
        spdlog::debug("[ {} >> {} ] (ec: {} , bytes: {})", ep1_, ep2_, ec.message(), bytes);
        if(ec)
        {
            return;
        }
        
        s1_.async_read_some(asio::buffer(buf1_), [this, self = this->shared_from_this()](error_code ec, size_t bytes)
        {
            handle_read_s1(ec, bytes);
        });
    }

    void handle_read_s2(error_code ec, size_t bytes)
    {
        spdlog::debug("[ {} -> {} ] (ec: {} , bytes: {})", ep2_, ep1_, ec.message(), bytes);
        if(ec)
        {
            return;
        }

        handler_();
        
        asio::async_write(s1_, asio::buffer(buf2_.data(), bytes), [this, self = this->shared_from_this()](error_code ec, size_t bytes)
        {
            handle_write_s1(ec, bytes);
        });
    }

    void handle_write_s1(error_code ec, size_t bytes)
    {
        spdlog::debug("[ {} >> {} ] (ec: {} , bytes: {})", ep2_, ep1_, ec.message(), bytes);
        if(ec)
        {
            return;
        }
        
        s2_.async_read_some(asio::buffer(buf2_), [this, self = this->shared_from_this()](error_code ec, size_t bytes)
        {
            handle_read_s2(ec, bytes);
        });
    }

    Stream1 & s1_;
    Stream2 & s2_;
    Buffer & buf1_;
    Buffer & buf2_;
    Handler handler_;
    std::string ep1_;
    std::string ep2_;
};

}

