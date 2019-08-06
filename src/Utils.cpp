#include <string>
#include <cstring>
#include <boost/format.hpp>
#include <arpa/inet.h>
#include <linux/if.h>
#include <sys/ioctl.h>
#include <stropts.h>
#include "Utils.h"

std::string Utils::toMacString(uint8_t mac[6])
{
    return boost::str(boost::format("%02x:%02x:%02x:%02x:%02x:%02x") % int(mac[0]) % int(mac[1]) % int(mac[2]) % int(mac[3]) % int(mac[4]) % int(mac[5]));
}

std::string Utils::toIpString(uint8_t ip[4])
{
    return boost::str(boost::format("%d.%d.%d.%d") % int(ip[0]) % int(ip[1]) % int(ip[2]) % int(ip[3]));
}

std::string Utils::toIpString(uint32_t ipInt)
{
    auto ip = reinterpret_cast<uint8_t*>(&ipInt);
    return boost::str(boost::format("%d.%d.%d.%d") % int(ip[0]) % int(ip[1]) % int(ip[2]) % int(ip[3]));
}

void Utils::getMyMac(const char* dev, uint8_t myMac[6])
{
    struct ifreq myMacIfr;
    strncpy(myMacIfr.ifr_name, dev, IFNAMSIZ - 1);
    auto sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    auto ret = ioctl(sock, SIOCGIFHWADDR, &myMacIfr);
    close(sock);

    if(ret == -1)
        throw std::runtime_error("Failed to get Mac address");

    memcpy(myMac, myMacIfr.ifr_addr.sa_data, 6);
}

void Utils::getMyIp(const char* dev, uint8_t myIp[4])
{
    struct ifreq myIpIfr;
    strncpy(myIpIfr.ifr_name, dev, IFNAMSIZ - 1);
    auto sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    auto ret = ioctl(sock, SIOCGIFADDR, &myIpIfr);
    close(sock);
    if(ret == -1)
        throw std::runtime_error("Failed to get IP address");

    memcpy(myIp, &((struct sockaddr_in*)&myIpIfr.ifr_addr)->sin_addr, 4);
}
