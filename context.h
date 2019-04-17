#pragma once

#include <boost/noncopyable.hpp>
#include <string>
#include <vector>

namespace shadowsocks
{

class context
{
public:
    std::string algo_spec;
    std::vector<uint8_t> key;
};

}
