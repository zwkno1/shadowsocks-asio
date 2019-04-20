#pragma once

#include <cstring>
#include <variant>

#include <asio.h>

namespace shadowsocks
{

// [1-byte type][variable-length host][2-byte port]
// 0x01: host is a 4-byte IPv4 address.
// 0x03: host is a variable length string, starting with a 1-byte length, followed by up to 255-byte domain name.
// 0x04: host is a 16-byte IPv6 address.
enum parse_result : uint8_t
{
	parse_ok,
	parse_need_more,
	parse_invalid_address,
};

enum AdressType : uint8_t
{
	IPV4 = 0x01,
	DOMAINNAME = 0x03,
	IPV6 = 0x04,
};

class request
{
public:
	request()
	    : type_(0)
	    , port_(0)
	{
	}

	size_t bytes() const
	{
		switch (type_)
		{
		case IPV4:
			return 7;
		case DOMAINNAME:
			return 4 + std::get<std::string>(addr_).size();
		case IPV6:
			return 19;
		default:
			return 0;
		}
	}

	uint8_t type() const
	{
		return type_;
	}

	asio::ip::address address() const
	{
		switch (type_)
		{
		case IPV4:
			return asio::ip::address_v4{std::get<asio::ip::address_v4::bytes_type>(addr_)};
		case IPV6:
			return asio::ip::address_v6{std::get<asio::ip::address_v6::bytes_type>(addr_)};
		default:
			return asio::ip::address{};
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

	parse_result parse(uint8_t *data, size_t size)
	{
		if(size < 4)
			return parse_need_more;
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
			addr_ = addr;
			port_ = (uint16_t{data[5]} << 8) | data[6];
			return parse_ok;
		}
		case DOMAINNAME:
		{
			uint8_t addrlen = data[1];
			addr_ = std::string {reinterpret_cast<char *>(&data[2]), addrlen};
			port_ = (uint16_t{data[addrlen+2]} << 8) | data[addrlen+3];
			return parse_ok;
		}
		case IPV6:
		{
			asio::ip::address_v6::bytes_type addr;
			std::memcpy(addr.data(), &data[1], 16);
			addr_ = addr;
			port_ = (uint16_t{data[17]} << 8) | data[18];
			return parse_ok;
		}
		default:
			return parse_invalid_address;
		}
    }

private:
    uint8_t type_;

    std::variant<
	    asio::ip::address_v6::bytes_type,
	    asio::ip::address_v4::bytes_type,
	    std::string
	> addr_;

	uint16_t port_;
};

}
