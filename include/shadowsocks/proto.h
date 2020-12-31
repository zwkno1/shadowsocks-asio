#pragma once

#include <cstring>
#include <variant>

#include <shadowsocks/asio.h>

namespace shadowsocks
{

// [1-byte type][variable-length host][2-byte port]
// 0x01: host is a 4-byte IPv4 address.
// 0x03: host is a variable length string, starting with a 1-byte length, followed by up to 255-byte domain name.
// 0x04: host is a 16-byte IPv6 address.

enum parse_result : uint8_t
{
    parse_ok = 0,
    parse_need_more,
    parse_invalid_address,
    parse_invalid_version,
    parse_cmd_unsupported,
    parse_reserve_nonzero,
};

enum AdressType : uint8_t
{
    IPV4 = 0x01,
    DOMAINNAME = 0x03,
    IPV6 = 0x04,
};

const uint8_t SOCKS5_VERSION = 5;

const uint8_t SOCKS5_CONNECT = 1;
const uint8_t SOCKS5_BIND = 2;
const uint8_t SOCKS5_UDP_ASSOCIATE = 3;

class request
{
public:
    request()
        : type_(0)
        , port_(0)
    {
    }
    
    uint8_t type() const
    {
        return type_;
    }
    
    const asio::ip::address & address() const
    {
        switch (type_)
        {
        case IPV4:
        case IPV6:
            return std::get<asio::ip::address>(addr_);
        default:
        {
            static asio::ip::address null_addr;
            return null_addr;
        }
        }
    }
    
    const std::string & domain() const
    {
        return std::get<std::string>(addr_);
    }
    
    uint16_t port() const
    {
        return port_;
    }
    
    parse_result parse(asio::streambuf & buf)
    {
        auto data = static_cast<const uint8_t *>(buf.data().data());
        const size_t size = buf.size();
        std::cout << __func__ << ", size: " << size << std::endl;

        if(size < 4){
            return parse_need_more;
        }

        type_ = data[0];
        switch (type_)
        {
        case IPV4:
        {
            if(size < 7)
            {
                return parse_need_more;
            }
            asio::ip::address_v4::bytes_type addr;
            std::memcpy(addr.data(), &data[1], 4);
            addr_ = asio::ip::address_v4{addr};
            port_ = (uint16_t{data[5]} << 8) | data[6];
            buf.consume(7);
            return parse_ok;
        }
        case DOMAINNAME:
        {
            uint8_t addrlen = data[1];
            if(size < addrlen + 4)
            {
                return parse_need_more;
            }
            addr_ = std::string {reinterpret_cast<const char *>(&data[2]), addrlen};
            port_ = (uint16_t{data[addrlen+2]} << 8) | data[addrlen+3];
            buf.consume(addrlen+4);
            return parse_ok;
        }
        case IPV6:
        {
            if(size < 19)
            {
                return parse_need_more;
            }
            asio::ip::address_v6::bytes_type addr;
            std::memcpy(addr.data(), &data[1], 16);
            addr_ = asio::ip::address_v6{addr};
            port_ = (uint16_t{data[17]} << 8) | data[18];
            buf.consume(19);
            return parse_ok;
        }
        default:
            return parse_invalid_address;
        }
    }
    
private:
    uint8_t type_;
    
    std::variant<
    asio::ip::address,
    std::string
    > addr_;
    
    uint16_t port_;
};

class socks5_handshake_request
{
public:
    socks5_handshake_request()
        : nmethod_(0)
    {
    }
    
    size_t bytes()
    {
        return nmethod_ + 2;
    }
    
    size_t nmethod() const
    {
        return nmethod_;
    }
    
    uint8_t method(size_t index) const
    {
        return methods_[index];
    }
    
    parse_result parse(const uint8_t *data, size_t size)
    {
        if(size < 2)
        {
            return parse_need_more;
        }
        
        if(data[0] != SOCKS5_VERSION)
        {
            return parse_invalid_version;
        }
        
        nmethod_ = data[1];
        
        if(size < nmethod_ + 2)
        {
            return parse_need_more;
        }
        
        std::memcpy(methods_.data(), data + 2, nmethod_);
        
        return parse_ok;
    }
private:
    uint8_t nmethod_;
    std::array<uint8_t, 255> methods_;
};

class socks5_handshake_response
{
public:
    socks5_handshake_response()
    {
    }
    
    size_t bytes() const
    {
        return 2;
    }
    
    uint8_t & method()
    {
        return method_;
    }
    
    void copy_to(uint8_t * dst)
    {
        dst[0] = SOCKS5_VERSION;
        dst[1] = method_;
    }
private:
    uint8_t method_;
};

/*
 *  The SOCKS request is formed as follows:
 *      +----+-----+-------+------+----------+----------+
 *      |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
 *      +----+-----+-------+------+----------+----------+
 *      | 1  |  1  | X'00' |  1   | Variable |    2     |
 *      +----+-----+-------+------+----------+----------+
 *          
 *  Where:
 *      o  VER    protocol version: X'05'
 *      o  CMD
 *         o  CONNECT X'01'
 *         o  BIND X'02'
 *         o  UDP ASSOCIATE X'03'
 *      o  RSV    RESERVED
 *      o  ATYP   address type of following address
 *         o  IP V4 address: X'01'
 *         o  DOMAINNAME: X'03'
 *         o  IP V6 address: X'04'
 *      o  DST.ADDR       desired destination address
 *      o  DST.PORT desired destination port in network octet
 *         order
 */

class socks5_request
{
public:
    socks5_request()
        : cmd_(0)
        , type_(0)
    {
    }
    
    size_t bytes() const
    {
        switch (type_)
        {
        case IPV4:
            return 10;
        case DOMAINNAME:
            return 7 + std::get<std::string>(addr_).size();
        case IPV6:
            return 22;
        default:
            return 0;
        }
    }
    
    uint8_t cmd() const
    {
        return cmd_;
    }
    
    uint8_t type() const
    {
        return type_;
    }
    
    const asio::ip::address & address() const
    {
        switch (type_)
        {
        case IPV4:
        case IPV6:
            return std::get<asio::ip::address>(addr_);
        default:
        {
            static asio::ip::address null_addr;
            return null_addr;
        }
        }
    }
    
    const std::string & domain() const
    {
        return std::get<std::string>(addr_);
    }
    
    uint16_t port() const
    {
        return port_;
    }
    
    // convert to shadowsocks request
    size_t copy_to(uint8_t * data)
    {
        data[1] = type_;
        size_t offset;
        switch(type_)
        {
            case IPV4:
            {
                asio::ip::address_v4::bytes_type addr = address().to_v4().to_bytes();
                std::memcpy(&data[1], addr.data(), addr.size());
                offset = 5;
            }
            case DOMAINNAME:
            {
                data[1] = domain().size();
                std::memcpy(&data[2], domain().data(), domain().size());
                offset = 2 + domain().size();
            }
            case IPV6:
            {
                asio::ip::address_v6::bytes_type addr = address().to_v6().to_bytes();
                std::memcpy(&data[1], addr.data(), addr.size());
                offset = 17;
            }
            default:
            {
                return 0;
            }
        }
        data[offset] = ((port_ >> 8) & 0xff);
        data[offset+1] = (port_ & 0xff);
        return offset + 2;
    }
    
    parse_result parse(const uint8_t * data, size_t size)
    {
        if(size < 7)
            return parse_need_more;
        if(data[0] != SOCKS5_VERSION)
            return parse_invalid_version;
        // only support connect current
        if(data[1] != 1)
            return parse_cmd_unsupported;
        cmd_ = data[1];
        if(data[2] != 0)
            return parse_reserve_nonzero;
        
        type_ = data[3];
        switch (type_)
        {
        case IPV4:
        {
            if(size < 10)
            {
                return parse_need_more;
            }
            asio::ip::address_v4::bytes_type addr;
            std::memcpy(addr.data(), &data[4], 4);
            addr_ = asio::ip::address_v4{addr};
            port_ = (uint16_t{data[8]} << 8) | data[9];
            return parse_ok;
        }
        case DOMAINNAME:
        {
            uint8_t addrlen = data[4];
            if(size < addrlen + 7)
            {
                return parse_need_more;
            }
            addr_ = std::string {reinterpret_cast<const char *>(&data[5]), addrlen};
            port_ = (uint16_t{data[addrlen+5]} << 8) | data[addrlen+6];
            return parse_ok;
        }
        case IPV6:
        {
            if(size < 22)
            {
                return parse_need_more;
            }
            asio::ip::address_v6::bytes_type addr;
            std::memcpy(addr.data(), &data[4], 16);
            addr_ = asio::ip::address_v6{addr};
            port_ = (uint16_t{data[20]} << 8) | data[21];
            return parse_ok;
        }
        default:
            return parse_invalid_address;
        }
    }
    
private:
    uint8_t cmd_;
    uint8_t type_;
    
    std::variant<
    asio::ip::address,
    std::string
    > addr_;
    
    uint16_t port_;
    
};

}
