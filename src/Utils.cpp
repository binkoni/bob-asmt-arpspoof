#include <string>
#include <cstring>
#include <arpa/inet.h>
#include <linux/if.h>
#include <sys/ioctl.h>
#include <stropts.h>
#include <iostream>
#include "Utils.h"
#include "ArpHeader.h"

void Utils::getMyMac(const char* iface, uint8_t myMac[6])
{
    struct ifreq myMacIfr;
    strncpy(myMacIfr.ifr_name, iface, IFNAMSIZ - 1);
    auto sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    auto ret = ioctl(sock, SIOCGIFHWADDR, &myMacIfr);
    close(sock);

    if(ret == -1)
        throw std::runtime_error("Failed to get Mac address");

    memcpy(myMac, myMacIfr.ifr_addr.sa_data, 6);
}


void Utils::getMyIp(const char* iface, uint8_t myIp[4])
{
    struct ifreq myIpIfr;
    strncpy(myIpIfr.ifr_name, iface, IFNAMSIZ - 1);
    auto sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    auto ret = ioctl(sock, SIOCGIFADDR, &myIpIfr);
    close(sock);
    if(ret == -1)
        throw std::runtime_error("Failed to get IP address");

    memcpy(myIp, &((struct sockaddr_in*)&myIpIfr.ifr_addr)->sin_addr, 4);
}

void Utils::queryMac(pcap_t* handle, uint8_t myMac[6], uint8_t myIp[4], uint8_t otherIp[4], uint8_t otherMac[6])
{
    struct bpf_program prog;
    auto filterString = Utils::toFilterString(myMac, otherIp);
    std::cout << "filter string is " << filterString << std::endl;

    if(pcap_compile(handle, &prog, filterString.c_str(), 0, *reinterpret_cast<uint32_t*>(myIp)) == -1)
    {
        throw std::runtime_error{"Failed to compile filter"};
    }

    if(pcap_setfilter(handle, &prog) == -1)
    {
        throw std::runtime_error{"Failed to set filter"};
    }

    ArpHeader::request(
        handle,
        myMac,
        myIp,
        otherIp
    );

    struct pcap_pkthdr* pktHdr;
    const u_char* pkt;

    pcap_next_ex(handle, &pktHdr, &pkt);
    
    auto arpPkt = dynamic_cast<ArpHeader*>(Header::parse(pkt, pktHdr->caplen));
    auto arpHdr = reinterpret_cast<ArpHeaderStruct*>(arpPkt->headerStruct());
    memcpy(otherMac, arpHdr->sha, 6);
}
