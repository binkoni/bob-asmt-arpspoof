#include <string>
#include <cstring>
#include <arpa/inet.h>
#include <linux/if.h>
#include <sys/ioctl.h>
#include <stropts.h>
#include "Utils.h"


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
