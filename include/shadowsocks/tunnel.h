#pragma once


#include <shadowsocks/asio.h>

namespace shadowsocks
{

class tunnel
{
public:
    template <typename InputStream, typename OutputStream, typename OnRead, typename OnWrite>
    static void run(asio::yield_context yield, InputStream & input,OutputStream & output, asio::streambuf & buffer, size_t prepare_size, OnRead && on_read, OnWrite && on_write) {
		if(buffer.size() != 0) {
			asio::async_write(output, buffer.data(), yield);
			on_write(buffer.size());
			buffer.consume(buffer.size());
		}
		for (;;) {
			size_t nbytes = input.async_read_some(buffer.prepare(prepare_size), yield);
			on_read(nbytes);
			buffer.commit(nbytes);
			asio::async_write(output, buffer.data(), yield);
			on_write(buffer.size());
            buffer.consume(buffer.size());
		}
	}
};

} // namespace shadowsocks
