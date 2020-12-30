
#pragma once

#include "boost/asio/spawn.hpp"
#include <vector>

#include <spdlog/spdlog.h>

#include <shadowsocks/asio.h>
#include <shadowsocks/cipher/stream.h>
#include <shadowsocks/ss_config.h>
#include <shadowsocks/proto.h>
#include <shadowsocks/tunnel.h>

namespace shadowsocks
{

#if 0
class client_session : private enable_shared_from_this<client_session>
{
public:
    client_session(tcp::socket && socket, const ss_config & config)
        : local_(std::move(socket))
        , remote_(tcp::socket{socket.get_io_context()}, *config.cipher, config.key)
        , rlen_(0)
        , timer_(socket.get_io_context())
        , active_(chrono::steady_clock::now())
        , config_(config)
    {
        ++count();
    }

    ~client_session()
    {
        --count();
    }

    void start(asio::yield_context yield)
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
            if(ec || (chrono::duration_cast<chrono::seconds>(chrono::steady_clock::now() - active_).count() > config_.timeout))
            {
                error_code ec;
                local_.shutdown(asio::socket_base::shutdown_both, ec);
                remote_.next_layer().shutdown(asio::socket_base::shutdown_both, ec);
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
        spdlog::debug("start : {}", start);
        
        start_ = start;
        for(;;)
        {
            switch(start_)
            {
            case 0:
                // read local socks5 handshake
                local_.set_option(tcp::no_delay{true});
                local_.set_option(asio::socket_base::keep_alive{true});
                local_.async_read_some(asio::buffer(rbuf_.data() + rlen_, rbuf_.size() - rlen_), [this, self = shared_from_this()](error_code ec, size_t bytes)
                {
                    (*this)(ec, bytes, ++start_);
                });
                return;
            case 1:
                // parse socks5 handshake
                spdlog::debug("socks5 handshake: {}", bytes);
                rlen_ += bytes;
                switch(handshake_.parse(rbuf_.data(), rlen_))
                {
                case parse_ok:
                {
                    spdlog::debug("parse socks5 handshake ok");
                    size_t request_len = handshake_.bytes();
                    rlen_ -= request_len;
                    if(rlen_ != 0)
                    {
                        std::memmove(rbuf_.data(), rbuf_.data()+request_len, rlen_);
                    }
                    /*
                     *  socks5 handshake reply
                     *  +----+--------+
                     *  |VER | METHOD |
                     *  +----+--------+
                     *  | 1  |   1    |
                     *  +----+--------+
                     */
                    wbuf_[0] = SOCKS5_VERSION;
                    wbuf_[1] = 0;
                    
                    boost::asio::async_write(local_, boost::asio::buffer(wbuf_.data(), 2), [this, self = shared_from_this()](error_code ec, size_t bytes)
                    {
                        (*this)(ec, bytes, ++start_);
                    });
                    return;
                }
                case parse_need_more:
                    spdlog::debug("parse socks5 handshake needmore");
                    --start_;
                    continue;
                default:
                    spdlog::error("bad proto, state: {}", start);
                    return;
                }
            case 2:
                // read local socks5 request
                spdlog::debug("read socks5 request, rlen: {}", rlen_);
                local_.async_read_some(asio::buffer(rbuf_.data() + rlen_, rbuf_.size() - rlen_), [this, self = shared_from_this()](error_code ec, size_t bytes)
                {
                    (*this)(ec, bytes, ++start_);
                });
                return;
            case 3:
                // parse local socks5 request
                rlen_ += bytes;
                switch(request_.parse(rbuf_.data(), rlen_))
                {
                case parse_ok:
                {
                    // local socks5 response
                    /*
                     *    +----+-----+-------+------+----------+----------+
                     *    |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
                     *    +----+-----+-------+------+----------+----------+
                     *    | 1  |  1  | X'00' |  1   | Variable |    2     |
                     *    +----+-----+-------+------+----------+----------+
                     *
                     *      o  VER    protocol version: X'05'
                     *      o  REP    Reply field:
                     *         o  X'00' succeeded
                     *         o  X'01' general SOCKS server failure
                     *         o  X'02' connection not allowed by ruleset
                     *         o  X'03' Network unreachable
                     *         o  X'04' Host unreachable
                     *         o  X'05' Connection refused
                     *         o  X'06' TTL expired
                     *         o  X'07' Command not supported
                     *         o  X'08' Address type not supported
                     *         o  X'09' to X'FF' unassigned
                     *      o  RSV    RESERVED
                     *      o  ATYP   address type of following address
                     */
                    size_t wlen = 10;
                    wbuf_[0] = SOCKS5_VERSION;
                    wbuf_[1] = 0;
                    wbuf_[2] = 0;
                    wbuf_[3] = IPV4; 
                    
                    spdlog::debug("parse socks5 request ok, cmd: {}", (size_t)request_.cmd());
                    if(request_.cmd() == SOCKS5_UDP_ASSOCIATE)
                    {
                        tcp::endpoint ep = local_.local_endpoint();
                        if(ep.address().is_v4())
                        {
                            wbuf_[3] = IPV4;
                            auto addr = ep.address().to_v4().to_bytes();
                            std::memcpy(&wbuf_[4], addr.data(), addr.size());
                            wbuf_[4 + addr.size()] = ((ep.port() >> 8) & 0xff);
                            wbuf_[5 + addr.size()] = (ep.port() & 0xff);
                            wlen = 6 + addr.size();
                        }
                        else
                        {
                            wbuf_[3] = IPV6;
                            auto addr = ep.address().to_v6().to_bytes();
                            std::memcpy(&wbuf_[4], addr.data(), addr.size());
                            wbuf_[4 + addr.size()] = ((ep.port() >> 8) & 0xff);
                            wbuf_[5 + addr.size()] = (ep.port() & 0xff);
                            wlen = 6 + addr.size();
                        }
                    }
                    else if(request_.cmd() != SOCKS5_CONNECT)
                    {
                        // not supported
                        wbuf_[1] = 7;
                    }
                    
                    asio::async_write(local_, asio::buffer(wbuf_.data(), wlen), [this, self = shared_from_this()](error_code ec, size_t bytes)
                    {
                        (*this)(ec, bytes, ++start_);
                    });
                    return;
                }
                case parse_need_more:
                    spdlog::debug("parse socks5 request needmore");
                    --start_;
                    continue;
                default:
                    spdlog::error("bad proto, state: {}", start);
                    return;
                }
            case 4:
            {
                // local socks5 response finished
                if(request_.cmd() == SOCKS5_UDP_ASSOCIATE)
                {
                    local_.async_wait(tcp::socket::wait_error, [self = shared_from_this()](error_code ec)
                    {
                        //udp finished
                    });
                }
                else if(request_.cmd() == SOCKS5_CONNECT)
                {
                    // connect to ss-server 
                    tcp::endpoint endpoint = {asio::ip::make_address(config_.server_address), config_.server_port};
                    remote_.next_layer().async_connect(endpoint, [this, self = shared_from_this()](error_code ec)
                    {
                        (*this)(ec, 0, ++start_);
                    });
                }
                return;
            }
            case 5:
            {
                // start socks5 connect
                rlen_ -= 3;
                std::memmove(rbuf_.data(), rbuf_.data()+3, rlen_);
                
                if(config_.no_delay.value_or(false))
                {
                    remote_.next_layer().set_option(tcp::no_delay{true});
                }
                else
                {
                    local_.set_option(tcp::no_delay{false});
                }
                remote_.next_layer().set_option(asio::socket_base::keep_alive{true});
                
                // start tunnel
                (tunnel_ = make_shared<tunnel_type>(local_, remote_, rbuf_, wbuf_, [this, self = shared_from_this()](){ active_ = chrono::steady_clock::now(); })).lock()->start(rlen_, 0);
                return;
            }
            default:
                spdlog::error("bug");
                return;
            }
        }
    }
    
    typedef std::array<uint8_t, max_cipher_block_size + 1024> buffer_type;
    typedef tunnel<tcp::socket, stream<tcp::socket>, buffer_type, std::function<void()> > tunnel_type;

    tcp::socket local_;
    
    stream<tcp::socket> remote_;

    weak_ptr<tunnel_type> tunnel_;

    socks5_handshake_request handshake_;
    
    socks5_request request_;

    size_t rlen_;

    buffer_type rbuf_;
    buffer_type wbuf_;
    
    asio::steady_timer timer_;
    
    chrono::steady_clock::time_point active_;
    
    const ss_config & config_;
    
    int start_;
};

#endif

}
