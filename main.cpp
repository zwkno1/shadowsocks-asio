#include <iostream>
#include <stream.h>

int main()
{
    boost::asio::io_context ioc;

    boost::asio::ip::tcp::socket sock{ioc};
    shadowsocks::context ctx;
    ctx.algo_spec = "ChaCha(20)";
    ctx.key.resize(32);

    shadowsocks::stream<boost::asio::ip::tcp::socket> ss{sock, ctx};
    std::array<char, 1024> buf;

    ss.async_read(boost::asio::buffer(buf), [](boost::system::error_code ec, size_t bytes)
    {
       if(ec)
       {
           std::cout << ec.message() << std::endl;
       }
    });


    ss.async_write(boost::asio::buffer(buf), [](boost::system::error_code ec, size_t bytes)
    {
       if(ec)
       {
           std::cout << ec.message() << std::endl;
       }
    });

    ioc.run();
    return 0;
}
