#pragma once

#include <boost/asio.hpp>

#include <shadowsocks/cipher_context.h>

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

	void operator()(boost::system::error_code ec, std::size_t bytes_transferred, int start = 0)
    {
        for(;;)
        {
            switch (start)
            {
            case 1:
                if(context_.engine_[0].iv_wanted_ != 0)
                {
                    boost::asio::async_read(next_layer_,
					    boost::asio::buffer(&*(context_.engine_[0].iv_.end() - context_.engine_[0].iv_wanted_), context_.engine_[0].iv_wanted_),
                        std::move(*this));
                    return;
                }
                start = 2;
                continue;
            case 0:
                if((context_.engine_[0].iv_wanted_ == 0) || ec)
                {
                    size_t bytes = bytes_transferred;
                    for(auto iter = boost::asio::buffer_sequence_begin(buffers_); iter != boost::asio::buffer_sequence_end(buffers_); ++iter)
                    {
                        if(bytes == 0)
                            break;
                        boost::asio::mutable_buffer buffer(*iter);
                        if (buffer.size() != 0)
                        {
							context_.engine_[0].cipher_->cipher1(reinterpret_cast<uint8_t *>(buffer.data()),  std::min(buffer.size(), bytes));
                            bytes -= std::min(buffer.size(), bytes);
                        }
                    }
                    handler_(ec, bytes_transferred);
                    return;
                }
                
                assert(bytes_transferred == context_.engine_[0].iv_wanted_);
                context_.engine_[0].iv_wanted_ = 0;
				context_.engine_[0].cipher_->set_iv(context_.engine_[0].iv_.data(), context_.engine_[0].iv_.size());
            default:
                next_layer_.async_read_some(buffers_, std::move(*this));
                return;
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
