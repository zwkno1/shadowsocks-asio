#pragma once

#include <asio.h>
#include <iostream>

namespace shadowsocks
{

template <typename Stream1, typename Stream2, typename Buffer, typename Arg>
class tunnel : public enable_shared_from_this<tunnel<Stream1, Stream2, Buffer, Arg>>
{
public:
    tunnel(Stream1 & s1, Stream2 & s2, Buffer & buf1, Buffer & buf2, Arg arg)
        : s1_(s1)
        , s2_(s2)
        , buf1_(buf1)
        , buf2_(buf2)
        , arg_(arg)
    {
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
            handle_write_s1(error_code{}, buf2_size);
        }
        else
        {
            handle_read_s2(error_code{}, 0);
        }
    }

    void handle_read_s1(error_code ec, size_t bytes)
    {
        if(ec)
            return;

        asio::async_write(s2_, asio::buffer(buf1_.data(), bytes), [this, self = this->shared_from_this()](error_code ec, size_t bytes)
        {
            handle_write_s2(ec, bytes);
        });
    }

    void handle_write_s2(error_code ec, size_t bytes)
    {
        if(ec)
            return;

        s1_.async_read_some(asio::buffer(buf1_), [this, self = this->shared_from_this()](error_code ec, size_t bytes)
        {
            handle_read_s1(ec, bytes);
        });
    }

    void handle_read_s2(error_code ec, size_t bytes)
    {
        if(ec)
            return;

        asio::async_write(s1_, asio::buffer(buf2_.data(), bytes), [this, self = this->shared_from_this()](error_code ec, size_t bytes)
        {
            handle_write_s1(ec, bytes);
        });
    }

    void handle_write_s1(error_code ec, size_t bytes)
    {
        if(ec)
            return;

        s2_.async_read_some(asio::buffer(buf2_), [this, self = this->shared_from_this()](error_code ec, size_t bytes)
        {
            handle_read_s2(ec, bytes);
        });
    }

    Stream1 & s1_;
    Stream2 & s2_;
    Buffer & buf1_;
    Buffer & buf2_;
    Arg arg_;
};

}

