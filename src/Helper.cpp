#include <string>
#include <boost/format.hpp>
#include <arpa/inet.h>
#include "Helper.h"
#include <iostream>

std::string Helper::toMacString(uint8_t mac[6])
{
    return boost::str(boost::format("%02x:%02x:%02x:%02x:%02x:%02x") % int(mac[0]) % int(mac[1]) % int(mac[2]) % int(mac[3]) % int(mac[4]) % int(mac[5]));
}

std::string Helper::toIpString(uint8_t ip[4])
{
    return boost::str(boost::format("%d.%d.%d.%d") % int(ip[0]) % int(ip[1]) % int(ip[2]) % int(ip[3]));
}

std::string Helper::toIpString(uint32_t ipInt)
{
    auto ip = reinterpret_cast<uint8_t*>(&ipInt);
    return boost::str(boost::format("%d.%d.%d.%d") % int(ip[0]) % int(ip[1]) % int(ip[2]) % int(ip[3]));
}
