#pragma once

#include <shadowsocks/asio.h>
#include <shadowsocks/cipher/cipher.h>
#include <shadowsocks/detail/cipher/read_op.h>
#include <shadowsocks/detail/cipher/write_op.h>

namespace shadowsocks
{

template <typename Stream>
class stream
{
public:
	typedef typename Stream::executor_type executor_type;

    template<typename Arg>
    stream(Arg && arg, const cipher_info & info, const cipher_key & key)
        : next_layer_(std::move(arg))
        , context_(std::make_unique<cipher_context>(info, key))
    {
    }
    
    stream(stream && other)
        : next_layer_(std::move(other.next_layer_))
        , context_(std::move(other.context_))
    {
    }
    
    stream & operator=(stream && other)
    {
        next_layer_ = std::move(other.next_layer_);
        context_ = std::move(other.context_);
        return *this;
    }

    Stream & next_layer()
    {
        return  next_layer_;
    }

    template <typename ConstBufferSequence, typename WriteHandler>
    BOOST_ASIO_INITFN_RESULT_TYPE(WriteHandler,
        void (error_code, std::size_t))
    async_write_some(const ConstBufferSequence& buffers,
        BOOST_ASIO_MOVE_ARG(WriteHandler) handler)
    {
      // If you get an error on the following line it means that your handler does
      // not meet the documented type requirements for a WriteHandler.
      BOOST_ASIO_WRITE_HANDLER_CHECK(WriteHandler, handler) type_check;

      asio::async_completion<WriteHandler,
        void (error_code, std::size_t)> init(handler);

      detail::async_write(next_layer_, *context_, wbuf_, buffers, init.completion_handler);

      return init.result.get();
    }

    template <typename MutableBufferSequence, typename ReadHandler>
    BOOST_ASIO_INITFN_RESULT_TYPE(ReadHandler,
        void (error_code, std::size_t))
    async_read_some(const MutableBufferSequence& buffers,
        BOOST_ASIO_MOVE_ARG(ReadHandler) handler)
    {
      // If you get an error on the following line it means that your handler does
      // not meet the documented type requirements for a ReadHandler.
      BOOST_ASIO_READ_HANDLER_CHECK(ReadHandler, handler) type_check;

      asio::async_completion<ReadHandler,
        void (error_code, std::size_t)> init(handler);

      detail::async_read(next_layer_, *context_, rbuf_, buffers, init.completion_handler);

      return init.result.get();
    }

private:
    Stream next_layer_;

    std::unique_ptr<cipher_context> context_;

    asio::streambuf rbuf_;
    
    asio::streambuf wbuf_;
};

} // namespace shadowsocks
