#pragma once

#include <boost/asio.hpp>

#include <stream/cipher_context.h>

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
            case 0:
                if(!ec)
                {
                    context_.handle_write();
                }
                handler_(ec, bytes_);
                return;
            default:
                boost::asio::const_buffer buffer(*boost::asio::buffer_sequence_begin(buffers_));
                size_t size = buffer.size();
                context_.encrypt(reinterpret_cast<const uint8_t *>(buffer.data()), size);
                bytes_ = size;
                boost::asio::async_write(next_layer_, context_.get_write_buffer(), std::move(*this));
            }
            return;
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
inline void async_write(Stream& next_layer, cipher_context & ctx, const ConstBufferSequence & buffers, Handler& handler)
{
	write_op<Stream, ConstBufferSequence, Handler>{next_layer, ctx, buffers, handler}(boost::system::error_code{}, 0, 1);
}

}
}
