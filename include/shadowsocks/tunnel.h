#pragma once

#include "boost/asio/io_context.hpp"
#include "boost/asio/spawn.hpp"
#include "boost/asio/streambuf.hpp"
#include "boost/asio/write.hpp"
#include <spdlog/spdlog.h>

#include <shadowsocks/asio.h>

namespace shadowsocks
{

class tunnel
{
public:
    template <typename Session, typename InputStream, typename OutputStream>
    static void run(asio::io_context & io_context, Session session, InputStream & input,OutputStream & output, asio::streambuf & buffer, size_t prepare_size) {
      asio::spawn(io_context, [session, &input, &output, &buffer, prepare_size](asio::yield_context yield) {
        try{
          if(buffer.size() != 0) {
            spdlog::debug("tunnel,  write: {}, data: {}", std::string{(const char *)buffer.data().data(), buffer.size()});
            asio::async_write(output, buffer.data(), yield);
            buffer.consume(buffer.size());
          }
          for (;;) {
            spdlog::debug("tunnel,  start read");
            size_t nbytes = input.async_read_some(buffer.prepare(prepare_size), yield);
            buffer.commit(nbytes);
            spdlog::debug("tunnel,  read size: {}", nbytes);
            spdlog::debug("tunnel,  write data: {}", std::string{(const char *)buffer.data().data(), buffer.size()});
            asio::async_write(output, buffer.data(), yield);
            buffer.consume(buffer.size());
            spdlog::debug("buffer size: {}", buffer.size());
            spdlog::debug("tunnel,  write size: {}", nbytes);
          }
        }catch(const system_error & err){
            spdlog::debug("tunnel,  error: {}", err.what());
        }
      });
    }
};

}

