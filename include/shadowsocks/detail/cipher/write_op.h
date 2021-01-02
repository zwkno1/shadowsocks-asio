#pragma once

#include <shadowsocks/asio.h>
#include <shadowsocks/cipher/cipher.h>

namespace shadowsocks
{
namespace detail
{

template <typename Stream, typename ConstBufferSequence, typename Handler>
class write_op
{
public:
    write_op(Stream & next_layer, cipher_context & ctx, asio::streambuf & wbuf, const ConstBufferSequence & buffers, Handler & h)
        : next_layer_(next_layer)
        , context_(ctx)
        , wbuf_(wbuf)
        , buffers_(buffers)
        , handler_(std::move(h))
        , nbytes_(0)
    {
    }

    void operator()(error_code ec, std::size_t nbytes, int start = 0)
    {
        for(;;)
        {
            switch (start)
            {
            case 0:
                wbuf_.consume(nbytes);
                handler_(ec, nbytes_);
                return;
            default:
                asio::const_buffer buffer(*asio::buffer_sequence_begin(buffers_));
                nbytes_ = buffer.size();
                context_.encrypt(buffer, wbuf_);
                asio::async_write(next_layer_, wbuf_.data(), std::move(*this));
                return;
            }
        }
    }

private:
    Stream & next_layer_;

    cipher_context & context_;

    asio::streambuf & wbuf_;
    
    ConstBufferSequence buffers_;

    Handler handler_;
    
    size_t nbytes_;
};

template <typename Stream, typename ConstBufferSequence, typename Handler>
inline void async_write(Stream& next_layer, cipher_context & ctx, asio::streambuf & wbuf, const ConstBufferSequence & buffers, Handler& handler)
{
    write_op<Stream, ConstBufferSequence, Handler>{next_layer, ctx, wbuf, buffers, handler}(error_code{}, 0, 1);
}

} // namespace detail
} // namespace shadowsocks
