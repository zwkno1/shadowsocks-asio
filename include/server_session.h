#pragma once

#include <any>
#include <variant>
#include <vector>
#include <string_view>

#include <asio.h>

#include <shadowsocks/stream.h>
#include <proto.h>
#include <tunnel.h>

namespace shadowsocks
{

class server_session : public enable_shared_from_this<server_session>
{
public:
    server_session(tcp::socket && socket, cipher_context && cc)
        : local_(std::move(socket), std::move(cc))
        , remote_(socket.get_io_context())
        , resolver_(socket.get_io_service())
        , rlen_(0)
    {
        ++count();
    }

    ~server_session()
    {
        --count();
    }

    void start()
    {
        (*this)();
    }

    static size_t & count()
    {
        static size_t count_ = 0;
        return count_;
    }

private:
    void operator()(error_code ec = error_code{}, size_t bytes = 0, int start = 0)
    {
        if(ec)
        {
            return;
        }

        for(;;)
        {
            switch (start)
            {
            case 0:
                local_.async_read_some(asio::buffer(rbuf_.data() + rlen_, rbuf_.size() - rlen_), [this, start, self = shared_from_this()](error_code ec, size_t bytes)
                {
                    (*this)(ec, bytes, start + 1);
                });
                return;
            case 1:
                rlen_ += bytes;
                switch(request_.parse(rbuf_.data(), rlen_))
                {
                case parse_ok:
                {
                    size_t request_len = request_.bytes();
                    rlen_ -= request_len;
                    if(rlen_ != 0)
                    {
                        std::memcpy(rbuf_.data(), rbuf_.data()+request_len, rlen_);
                    }

                    switch (request_.type())
                    {
                    case DOMAINNAME:
                    {
                        //resolve
                        resolver_.async_resolve(request_.domain(), std::to_string(request_.port()), [this, self = shared_from_this(), start](error_code ec, tcp::resolver::results_type result)
                        {
                            if(ec || result.empty())
                            {
                                return;
                            }

                            remote_.open(result.begin()->endpoint().protocol());
                            remote_.async_connect(*result.begin(), [this, self = shared_from_this(), start](error_code ec)
                            {
                                (*this)(ec, 0, start + 1);
                            });

                        });
                        return;
                    }
                    case IPV4:
                    case IPV6:
                    {
                        tcp::endpoint ep{request_.address(), request_.port()};
                        remote_.open(ep.protocol());
                        remote_.async_connect(ep, [this, self = shared_from_this(), start](error_code ec)
                        {
                            (*this)(ec, 0, start + 1);
                        });
                        return;
                    }
                    default:
                        return;
                    }
                }
                case parse_need_more:
                    start = 0;
                    continue;
                default:
                    return;
                }
            default:
            {
                (tunnel_ = make_shared<tunnel_type>(local_, remote_, rbuf_, wbuf_, shared_from_this())).lock()->start(rlen_);
            }
                return;
            }
        }
    }

    typedef tunnel<stream<tcp::socket>, tcp::socket, std::array<uint8_t, 40960>, shared_ptr<server_session> > tunnel_type;

    stream<tcp::socket> local_;

    tcp::socket remote_;

    tcp::resolver resolver_;

    weak_ptr<tunnel_type> tunnel_;

    request request_;

    size_t rlen_;

    std::array<uint8_t, 40960> rbuf_;
    std::array<uint8_t, 40960> wbuf_;

};

}
