#pragma once

#include <boost/asio.hpp>
#include <engine.h>

namespace shadowsocks
{
namespace detail
{

template <typename Stream, typename ConstBufferSequence, typename Handler>
class write_op
{
public:
    write_op(Stream & next_layer, engine & eng, const ConstBufferSequence & buffers, Handler & h)
        : next_layer_(next_layer)
        , engine_(eng)
        , buffers_(buffers)
        , handler_(std::move(h))
    {
    }

    void operator()(boost::system::error_code ec,
        std::size_t bytes_transferred, int start = 0)
    {
        for(;;)
        {
            switch (start)
            {
            case 1:
                if(engine_.cipher_data_[1].iv_wanted_ != 0)
                {
                    boost::asio::async_write(next_layer_,
                        boost::asio::buffer(engine_.cipher_data_[1].iv_),
                        std::move(*this));
                    return;
                }
                start = 2;
                continue;
            case 0:
                if((engine_.cipher_data_[0].iv_wanted_ = 0) || ec)
                {

                    handler_(ec, bytes_transferred);
                    return;
                }

                engine_.cipher_data_[1].iv_wanted_ = 0;
                engine_.cipher_data_[1].cipher_->set_iv(engine_.cipher_data_[1].iv_.data(),
                        engine_.cipher_data_[1].iv_.size());
            default:
                for(auto iter = boost::asio::buffer_sequence_begin(buffers_); iter != boost::asio::buffer_sequence_end(buffers_); ++iter)
                {
                    boost::asio::const_buffer buffer(*iter);
                    if (buffer.size() != 0)
                    {
                        engine_.cipher_data_[0].cipher_->cipher1(reinterpret_cast<uint8_t *>(const_cast<void *>((buffer.data()))), buffer.size());
                    }
                }
                boost::asio::async_write(next_layer_, buffers_, std::move(*this));
                return;
            }
        }
    }

private:
    Stream & next_layer_;

    engine & engine_;

    ConstBufferSequence buffers_;

    Handler handler_;
};

template <typename Stream, typename ConstBufferSequence, typename Handler>
inline void async_write(Stream& next_layer, engine & eng, const ConstBufferSequence & buffers, Handler& handler)
{
    write_op<Stream, ConstBufferSequence, Handler>(next_layer, eng, buffers, handler)(boost::system::error_code(), 0, 1);
}

}
}
