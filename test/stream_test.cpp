#include <iostream>
#include <shadowsocks/stream.h>

int main()
{
    boost::asio::io_context ioc;

    std::vector<uint8_t> key;
    key.resize(32);

    boost::asio::ip::tcp::endpoint endpoint{boost::asio::ip::address::from_string("0.0.0.0"), 18888};
    boost::asio::ip::tcp::acceptor acceptor{ioc};
    acceptor.open(endpoint.protocol());
    acceptor.set_option(boost::asio::ip::tcp::acceptor::reuse_address{true});
    acceptor.bind(endpoint);
    acceptor.listen();
    boost::asio::ip::tcp::socket sock{ioc};
    std::function<void()> do_accept;
    do_accept = [&sock, &key, &acceptor, &do_accept]()
    {
        acceptor.async_accept(sock, [&sock, &key, &do_accept](boost::system::error_code ec)
        {
            if(ec)
            {
                std::cout << "accept: " << ec.message() << std::endl;
                return;
            }

            auto ss = std::make_shared<shadowsocks::stream<boost::asio::ip::tcp::socket>>(sock, shadowsocks::context{"ChaCha(20)", key});
            auto buf = std::make_shared<std::array<uint8_t, 1024>>();
            ss->async_read_some(boost::asio::buffer(*buf), [ss, buf](boost::system::error_code ec, size_t bytes)
            {
                if(ec)
                {
                    std::cout << "server read: " << ec.message() << std::endl;
                    return;
                }
                ss->async_write(boost::asio::buffer(buf->data(), bytes), [ss, buf](boost::system::error_code ec, size_t bytes)
                {
                    if(ec)
                    {
                        std::cout << "server write: " << ec.message() << std::endl;
                        return;
                    }
                });
            });
            do_accept();
        });
    };
    do_accept();

    std::array<char, 32> buf;
    std::string testData = "hello chacha!";

    boost::asio::ip::tcp::socket sock2{ioc};
    sock2.open(endpoint.protocol());
    sock2.async_connect(endpoint, [&sock2, &key, &testData, &buf](boost::system::error_code ec)
    {
        auto ss2 = std::make_shared<shadowsocks::stream<boost::asio::ip::tcp::socket>>(std::move(sock2), shadowsocks::context{"ChaCha(20)", key});
        if(ec)
        {
            std::cout << "client connect: " << ec.message() << std::endl;
            return;
        }

        //boost::system::error_code ec2;
        //ss2.next_layer().write_some(boost::asio::buffer(testData), ec2);
        //std::cout << ec2.message() << std::endl;
        ss2->async_write(boost::asio::buffer(testData.data(), testData.size()), [ss2, &buf](boost::system::error_code ec, size_t bytes)
        {
            if(ec)
            {
                std::cout << "client write: " << ec.message() << std::endl;
                return;
            }

            ss2->async_read_some(boost::asio::buffer(buf), [ss2, &buf](boost::system::error_code ec, size_t bytes)
            {
                if(ec)
                {
                    std::cout << "client read: " << ec.message() << std::endl;
                    return;
                }
                std::cout << std::string{buf.data(), bytes} << std::endl;
            });
        });
    });

    ioc.run();
    return 0;
}
