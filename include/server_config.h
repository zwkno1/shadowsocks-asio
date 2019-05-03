#pragma once

#include <serialization/serialization.h>

namespace shadowsocks
{

struct server_config
{
    std::string log_level;
    std::string server;
    uint16_t server_port;
    std::string method;
    std::string password;
    uint32_t timeout;
    uint32_t workers;
    
    SERIALIZATION_DEFINE(log_level, server, server_port, method, password, timeout, workers)
};

}
