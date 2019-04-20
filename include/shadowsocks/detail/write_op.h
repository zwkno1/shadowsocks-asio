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
	{
	}

	void operator()(boost::system::error_code ec, std::size_t bytes_transferred, int start = 0)
	{
		for(;;)
		{
			switch (start)
			{
			case 1:
				if(context_.engine_[1].iv_wanted_ != 0)
				{
					boost::asio::async_write(next_layer_,
					                         boost::asio::buffer(context_.engine_[1].iv_),
					        std::move(*this));
					return;
				}
				start = 2;
				continue;
			case 0:
				if((context_.engine_[1].iv_wanted_ == 0) || ec)
				{
					handler_(ec, bytes_transferred);
					return;
				}

				assert(bytes_transferred == context_.engine_[1].iv_wanted_);
				context_.engine_[1].iv_wanted_ = 0;
				context_.engine_[1].cipher_->set_iv(context_.engine_[1].iv_.data(), context_.engine_[1].iv_.size());
			default:
				for(auto iter = boost::asio::buffer_sequence_begin(buffers_); iter != boost::asio::buffer_sequence_end(buffers_); ++iter)
				{
					boost::asio::const_buffer buffer(*iter);
					if (buffer.size() != 0)
					{
						context_.engine_[1].cipher_->cipher1(reinterpret_cast<uint8_t *>(const_cast<void *>((buffer.data()))), buffer.size());
					}
				}
				boost::asio::async_write(next_layer_, buffers_, std::move(*this));
				return;
			}
		}
	}

private:
	Stream & next_layer_;

	cipher_context & context_;

	ConstBufferSequence buffers_;

	Handler handler_;
};

template <typename Stream, typename ConstBufferSequence, typename Handler>
inline void async_write(Stream& next_layer, cipher_context & ctx, const ConstBufferSequence & buffers, Handler& handler)
{
	write_op<Stream, ConstBufferSequence, Handler>{next_layer, ctx, buffers, handler}(boost::system::error_code{}, 0, 1);
}

}
}
