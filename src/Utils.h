#ifndef UTILS_H
#define UTILS_H

#include <string>
#include <boost/format.hpp>

namespace Utils
{
    void getMyMac(const char* dev, uint8_t myMac[6]);
    void getMyIp(const char* dev, uint8_t myIp[4]);

    inline std::string toMacString(uint8_t mac[6])
    {
        return boost::str(boost::format("%02x:%02x:%02x:%02x:%02x:%02x") % int(mac[0]) % int(mac[1]) % int(mac[2]) % int(mac[3]) % int(mac[4]) % int(mac[5]));
    }
    inline std::string toIpString(uint8_t ip[4])
    {
        return boost::str(boost::format("%d.%d.%d.%d") % int(ip[0]) % int(ip[1]) % int(ip[2]) % int(ip[3]));
    }
    inline std::string toIpString(uint32_t ipInt)
    {
        auto ip = reinterpret_cast<uint8_t*>(&ipInt);
        return boost::str(boost::format("%d.%d.%d.%d") % int(ip[0]) % int(ip[1]) % int(ip[2]) % int(ip[3]));
    }
    inline long toIpLong(uint8_t ip[4])
    {
        return *reinterpret_cast<long*>(ip);
    }
    inline uint8_t* fromIpLong(long& ip)
    {
        return reinterpret_cast<uint8_t*>(&ip);
    }
    inline uint8_t* fromIpSockAddr(struct sockaddr_in& ip)
    {
        return reinterpret_cast<uint8_t*>(&ip.sin_addr.s_addr);
    }
}

#endif
