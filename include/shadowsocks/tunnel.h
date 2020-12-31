#pragma once


#include <shadowsocks/asio.h>

namespace shadowsocks
{

class tunnel
{
public:
    template <typename Executor, typename Session, typename InputStream, typename OutputStream>
    static void run(const Executor & executor, Session session, InputStream & input,OutputStream & output, asio::streambuf & buffer, size_t prepare_size) {
      asio::spawn(executor, [session, &input, &output, &buffer, prepare_size](asio::yield_context yield) {
        try{
          if(buffer.size() != 0) {
            asio::async_write(output, buffer.data(), yield);
            buffer.consume(buffer.size());
          }
          for (;;) {
            size_t nbytes = input.async_read_some(buffer.prepare(prepare_size), yield);
            buffer.commit(nbytes);
            asio::async_write(output, buffer.data(), yield);
            buffer.consume(buffer.size());
          }
        }catch(const system_error & err){
            SPDLOG_INFO("tunnel,  error: {}", err.what());
        }
      });
    }
};

}

