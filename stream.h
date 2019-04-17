#pragma once

#include <boost/asio.hpp>
#include <context.h>
#include <engine.h>
#include <read_op.h>
#include <write_op.h>

namespace shadowsocks
{

template <typename Stream>
class stream
{
public:
    template<typename Arg>
    stream(Arg && arg, const context & ctx)
        : next_layer_(std::move(arg))
        , engine_(ctx)
    {
    }

    template <typename ConstBufferSequence, typename WriteHandler>
    BOOST_ASIO_INITFN_RESULT_TYPE(WriteHandler,
        void (boost::system::error_code, std::size_t))
    async_write(const ConstBufferSequence& buffers,
        BOOST_ASIO_MOVE_ARG(WriteHandler) handler)
    {
      // If you get an error on the following line it means that your handler does
      // not meet the documented type requirements for a WriteHandler.
      BOOST_ASIO_WRITE_HANDLER_CHECK(WriteHandler, handler) type_check;

      boost::asio::async_completion<WriteHandler,
        void (boost::system::error_code, std::size_t)> init(handler);

      detail::async_write(next_layer_, engine_, buffers, init.completion_handler);

      return init.result.get();
    }

    template <typename MutableBufferSequence, typename ReadHandler>
    BOOST_ASIO_INITFN_RESULT_TYPE(ReadHandler,
        void (boost::system::error_code, std::size_t))
    async_read(const MutableBufferSequence& buffers,
        BOOST_ASIO_MOVE_ARG(ReadHandler) handler)
    {
      // If you get an error on the following line it means that your handler does
      // not meet the documented type requirements for a ReadHandler.
      BOOST_ASIO_READ_HANDLER_CHECK(ReadHandler, handler) type_check;

      boost::asio::async_completion<ReadHandler,
        void (boost::system::error_code, std::size_t)> init(handler);

      detail::async_read(next_layer_, engine_, buffers, init.completion_handler);

      return init.result.get();
    }

private:
    Stream next_layer_;

    detail::engine engine_;
};

}
