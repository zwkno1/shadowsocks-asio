#pragma once

#include <boost/asio.hpp>
#include <spdlog/spdlog.h>

#include <stream/cipher_context.h>

namespace shadowsocks
{

namespace detail
{

template <typename Stream, typename MutableBufferSequence, typename Handler>
class read_op
{
public:
    read_op(Stream & next_layer, cipher_context & ctx, const MutableBufferSequence & buffers, Handler & h)
        : next_layer_(next_layer)
        , context_(ctx)
        , buffers_(buffers)
        , handler_(std::move(h))
    {
    }

	void operator()(boost::system::error_code ec, std::size_t bytes, int start = 0)
    {
        for(;;)
        {
            switch (start)
            {
            case 1:
            {
                boost::asio::mutable_buffer buffer(*boost::asio::buffer_sequence_begin(buffers_));
                if(buffer.size() < max_cipher_block_size)
                {
                    ec = shadowsocks::error::make_error_code(shadowsocks::error::cipher_buf_too_short);
                }
                
                if(ec)
                {
                    next_layer_.get_io_context().post([h = std::move(handler_), ec]()
                    {
                        h(ec, 0);
                    });
                    return;
                }
                
                spdlog::debug("decrypt result: {}", ec.message());
                size_t dec_bytes = 0;
                context_.decrypt(reinterpret_cast<uint8_t *>(buffer.data()), dec_bytes, ec);
                if(dec_bytes != 0)
                {
                    spdlog::debug("decrypt {} bytes: {}", dec_bytes, std::string((const char *)buffer.data(), dec_bytes));
                    next_layer_.get_io_context().post([h = std::move(handler_), dec_bytes]()
                    {
                        h(boost::system::error_code{}, dec_bytes);
                    });
                    return;
                }
                
                spdlog::debug("start read: {}", context_.get_read_buffer().size());
                next_layer_.async_read_some(context_.get_read_buffer(), std::move(*this));
            }
                return;
            case 0:
                spdlog::debug("handle read: {}, {}", ec.message(), bytes);
                if(ec)
                {
                    handler_(ec, 0);
                }
                context_.handle_read(bytes);
                start = 1;
                break;
            }
        }
    }

private:
    Stream & next_layer_;

    cipher_context & context_;

    MutableBufferSequence buffers_;

    Handler handler_;
};

template <typename Stream, typename MutableBufferSequence, typename Handler>
inline void async_read(Stream& next_layer, cipher_context & ctx, const MutableBufferSequence & buffers, Handler& handler)
{
    read_op<Stream, MutableBufferSequence, Handler>{next_layer, ctx, buffers, handler}(boost::system::error_code{}, 0, 1);
}

// add later
//template <typename Stream, typename Operation, typename Handler>
//inline void* asio_handler_allocate(std::size_t size,
//    io_op<Stream, Operation, Handler>* this_handler)
//{
//  return boost_asio_handler_alloc_helpers::allocate(
//      size, this_handler->handler_);
//}
//
//template <typename Stream, typename Operation, typename Handler>
//inline void asio_handler_deallocate(void* pointer, std::size_t size,
//    io_op<Stream, Operation, Handler>* this_handler)
//{
//  boost_asio_handler_alloc_helpers::deallocate(
//      pointer, size, this_handler->handler_);
//}
//
//template <typename Stream, typename Operation, typename Handler>
//inline bool asio_handler_is_continuation(
//    io_op<Stream, Operation, Handler>* this_handler)
//{
//  return this_handler->start_ == 0 ? true
//    : boost_asio_handler_cont_helpers::is_continuation(this_handler->handler_);
//}
//
//template <typename Function, typename Stream,
//    typename Operation, typename Handler>
//inline void asio_handler_invoke(Function& function,
//    io_op<Stream, Operation, Handler>* this_handler)
//{
//  boost_asio_handler_invoke_helpers::invoke(
//      function, this_handler->handler_);
//}
//
//template <typename Function, typename Stream,
//    typename Operation, typename Handler>
//inline void asio_handler_invoke(const Function& function,
//    io_op<Stream, Operation, Handler>* this_handler)
//{
//  boost_asio_handler_invoke_helpers::invoke(
//      function, this_handler->handler_);
//}
//
//template <typename Stream, typename Operation, typename Handler>
//inline void async_io(Stream& next_layer, stream_core& core,
//    const Operation& op, Handler& handler)
//{
//  io_op<Stream, Operation, Handler>(
//    next_layer, core, op, handler)(
//      boost::system::error_code(), 0, 1);
//}
//
//} // namespace detail
//} // namespace ssl
//
//template <typename Stream, typename Operation,
//    typename Handler, typename Allocator>
//struct associated_allocator<
//    ssl::detail::io_op<Stream, Operation, Handler>, Allocator>
//{
//  typedef typename associated_allocator<Handler, Allocator>::type type;
//
//  static type get(const ssl::detail::io_op<Stream, Operation, Handler>& h,
//      const Allocator& a = Allocator()) BOOST_ASIO_NOEXCEPT
//  {
//    return associated_allocator<Handler, Allocator>::get(h.handler_, a);
//  }
//};
//
//template <typename Stream, typename Operation,
//    typename Handler, typename Executor>
//struct associated_executor<
//    ssl::detail::io_op<Stream, Operation, Handler>, Executor>
//{
//  typedef typename associated_executor<Handler, Executor>::type type;
//
//  static type get(const ssl::detail::io_op<Stream, Operation, Handler>& h,
//      const Executor& ex = Executor()) BOOST_ASIO_NOEXCEPT
//  {
//    return associated_executor<Handler, Executor>::get(h.handler_, ex);
//  }
//};

}
}
