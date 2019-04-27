#pragma once

#include <boost/asio.hpp>
#include <shadowsocks/cipher_context.h>

namespace shadowsocks
{
namespace detail
{

template <typename Stream, typename ConstBufferSequence, typename Handler>
class write_op
{
public:
    write_op(Stream & next_layer, cipher_context & ctx, const ConstBufferSequence & buffers, Handler & h)
        : next_layer_(next_layer)
        , context_(ctx)
        , buffers_(buffers)
        , handler_(std::move(h))
        , bytes_(0)
    {
    }
    
    void operator()(boost::system::error_code ec, std::size_t bytes, int start = 0)
    {
        for(;;)
        {
            switch (start)
            {
            case 1:
                for(auto iter = boost::asio::buffer_sequence_begin(buffers_); iter != boost::asio::buffer_sequence_end(buffers_); ++iter)
                {
                    boost::asio::const_buffer buffer(*iter);
                    if (buffer.size() != 0)
                    {
                        context_.encrypt(buffer, ec);
                        if(ec)
                        {
                            handler_(ec, bytes_);
                            return;
                        }
                        bytes_ = buffer.size();
                        boost::asio::async_write(next_layer_, context_.get_write_buffer(), std::move(*this));
                        return;
                    }
                }
            default:
                handler_(ec, bytes_);
                return;
            }
        }
    }
    
private:
    Stream & next_layer_;
    
    cipher_context & context_;
    
    ConstBufferSequence buffers_;
    
    Handler handler_;
    
    size_t bytes_;
};

template <typename Stream, typename ConstBufferSequence, typename Handler>
inline void async_write_some(Stream& next_layer, cipher_context & ctx, const ConstBufferSequence & buffers, Handler& handler)
{
    write_op<Stream, ConstBufferSequence, Handler>{next_layer, ctx, buffers, handler}(boost::system::error_code{}, 0, 1);
}

}
}
