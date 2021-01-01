#pragma once

#include <shadowsocks/asio.h>
#include <shadowsocks/cipher/cipher.h>

namespace shadowsocks
{
namespace detail
{

template <typename Stream, typename MutableBufferSequence, typename Handler>
class read_op
{
public:
    read_op(Stream & next_layer, cipher_context & ctx, asio::streambuf & rbuf, const MutableBufferSequence & buffers, Handler & h)
        : next_layer_(next_layer)
        , context_(ctx)
        , rbuf_(rbuf)
        , buffers_(buffers)
        , handler_(std::move(h))
        , nbytes_(0)
    {
    }

    void operator()() {
        handler_(ec_, nbytes_);
    }

	void operator()(error_code ec, std::size_t nbytes, int start = 0)
    {
        for(;;)
        {
            switch (start)
            {
            case 1:
            case 2:
            {
                context_.decrypt(rbuf_, *asio::buffer_sequence_begin(buffers_), ec_, nbytes_);
                if(!ec_ && nbytes_ == 0) {
                    next_layer_.async_read_some(rbuf_.prepare((MAX_AEAD_BLOCK_SIZE+1)*2), std::move(*this));
                    return;
                }

                if (start == 1) {
                  asio::post(next_layer_.get_executor(), std::move(*this));
                  return;
                }

                (*this)();
                return;
            }
            case 0:
            {
                rbuf_.commit(nbytes);
                if(ec) {
                    ec_ = ec;
                    (*this)();
                    return;
                }
                start = 2;
                break;
            }
            }
        }
    }

private:
    Stream & next_layer_;

    cipher_context & context_;

    asio::streambuf & rbuf_;

    MutableBufferSequence buffers_;

    Handler handler_;
    
    error_code ec_;
    
    size_t nbytes_;
};

template <typename Stream, typename MutableBufferSequence, typename Handler>
inline void async_read(Stream& next_layer, cipher_context & ctx, asio::streambuf & rbuf, const MutableBufferSequence & buffers, Handler& handler)
{
    read_op<Stream, MutableBufferSequence, Handler>{next_layer, ctx, rbuf, buffers, handler}(error_code{}, 0, 1);
}

} // namespace detail
} // namespace shadowsocks
