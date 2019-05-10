#pragma once

#include <vector>

#include <shadowsocks/asio.h>
#include <shadowsocks/cipher/stream.h>
#include <shadowsocks/ss_config.h>
#include <shadowsocks/proto.h>
#include <shadowsocks/tunnel.h>

namespace shadowsocks
{

class server_session : public enable_shared_from_this<server_session>
{
public:
    server_session(tcp::socket && socket, const ss_config & config)
        : local_(std::move(socket), *config.cipher, config.key)
        , remote_(socket.get_io_context())
        , resolver_(socket.get_io_service())
        , rlen_(0)
        , timer_(socket.get_io_context())
        , active_(chrono::steady_clock::now())
        , config_(config)
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
        
        if(config_.timeout != 0)
        {
            start_timer();
        }
    }

    static size_t & count()
    {
        static size_t count_ = 0;
        return count_;
    }

private:
    void start_timer()
    {
        timer_.expires_from_now(chrono::seconds(config_.timeout));
        timer_.async_wait([this, self = shared_from_this()](error_code ec)
        {
            if(chrono::duration_cast<chrono::seconds>(chrono::steady_clock::now() - active_).count() > config_.timeout)
            {
                error_code ec;
                local_.next_layer().shutdown(asio::socket_base::shutdown_both, ec);
                remote_.shutdown(asio::socket_base::shutdown_both, ec);
            }
            else
            {
                start_timer();
            }
        });
    }
    
    void operator()(error_code ec = error_code{}, size_t bytes = 0, int start = 0)
    {
        if(ec)
        {
            return;
        }
        
        spdlog::debug("start: {}", start);

        start_ = start;
        for(;;)
        {
            switch (start_)
            {
            case 0:
                // read shadowsocks header
                local_.next_layer().set_option(tcp::no_delay{true});
                local_.next_layer().set_option(asio::socket_base::keep_alive{true});
                local_.async_read_some(asio::buffer(rbuf_.data() + rlen_, rbuf_.size() - rlen_), [this, self = shared_from_this()](error_code ec, size_t bytes)
                {
                    (*this)(ec, bytes, ++start_);
                });
                return;
            case 1:
                // parse shadowsocks header
                rlen_ += bytes;
                switch(request_.parse(rbuf_.data(), rlen_))
                {
                case parse_ok:
                {
                    size_t request_len = request_.bytes();
                    rlen_ -= request_len;
                    if(rlen_ != 0)
                    {
                        std::memmove(rbuf_.data(), rbuf_.data()+request_len, rlen_);
                    }

                    switch (request_.type())
                    {
                    case DOMAINNAME:
                    {
                        //resolve
                        resolver_.async_resolve(request_.domain(), std::to_string(request_.port()), [this, self = shared_from_this()](error_code ec, tcp::resolver::results_type result)
                        {
                            if(ec || result.empty())
                            {
                                return;
                            }

                            remote_.open(result.begin()->endpoint().protocol());
                            remote_.async_connect(*result.begin(), [this, self = shared_from_this()](error_code ec)
                            {
                                (*this)(ec, 0, ++start_);
                            });

                        });
                        return;
                    }
                    case IPV4:
                    case IPV6:
                    {
                        tcp::endpoint ep{request_.address(), request_.port()};
                        remote_.open(ep.protocol());
                        remote_.async_connect(ep, [this, self = shared_from_this()](error_code ec)
                        {
                            (*this)(ec, 0, ++start_);
                        });
                        return;
                    }
                    default:
                        return;
                    }
                }
                case parse_need_more:
                    start_ = 0;
                    continue;
                default:
                    spdlog::error("bad proto");
                    return;
                }
            case 2:
            {
                if(config_.no_delay.value_or(false))
                {
                    remote_.set_option(tcp::no_delay{true});
                }
                else
                {
                    local_.next_layer().set_option(tcp::no_delay{false});
                }
                
                remote_.set_option(asio::socket_base::keep_alive{true});
                
                (tunnel_ = make_shared<tunnel_type>(local_, remote_, rbuf_, wbuf_, [this, self = shared_from_this()](){ active_ = chrono::steady_clock::now(); })).lock()->start(rlen_);
            }
                return;
            default:
                spdlog::error("bug");
            }
        }
    }
    
    typedef std::array<uint8_t, shadowsocks::max_cipher_block_size + 1024> buffer_type;
    typedef tunnel<stream<tcp::socket>, tcp::socket, buffer_type, std::function<void()> > tunnel_type;

    stream<tcp::socket> local_;

    tcp::socket remote_;

    tcp::resolver resolver_;

    weak_ptr<tunnel_type> tunnel_;

    request request_;

    size_t rlen_;

    buffer_type rbuf_;
    buffer_type wbuf_;
    
    asio::steady_timer timer_;
    
    chrono::steady_clock::time_point active_;
    
    const ss_config & config_;
    
    int start_;
};

}
