#include <string>
#include <cstring>
#include <arpa/inet.h>
#include <linux/if.h>
#include <sys/ioctl.h>
#include <stropts.h>
#include <iostream>
#include "Utils.h"
#include "ArpPdu.h"

MacAddr Utils::getMyMac(const std::string& iface)
{
    struct ifreq myMacIfr;
    strncpy(myMacIfr.ifr_name, iface.c_str(), IFNAMSIZ - 1);
    auto sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    auto ret = ioctl(sock, SIOCGIFHWADDR, &myMacIfr);
    close(sock);

    if(ret == -1)
        throw std::runtime_error{"Failed to get Mac address"};

    return MacAddr{reinterpret_cast<uint8_t*>(myMacIfr.ifr_addr.sa_data)};
}

Ip4Addr Utils::getMyIp(const std::string& iface)
{
    struct ifreq myIpIfr;
    strncpy(myIpIfr.ifr_name, iface.c_str(), IFNAMSIZ - 1);
    auto sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    auto ret = ioctl(sock, SIOCGIFADDR, &myIpIfr);
    close(sock);
    if(ret == -1)
        throw std::runtime_error("Failed to get IP address");

    return Ip4Addr{((struct sockaddr_in*)&myIpIfr.ifr_addr)->sin_addr};
}

MacAddr Utils::queryMac(pcap_t* handle, const MacAddr& myMac, const Ip4Addr& myIp, const Ip4Addr& otherIp)
{
    /*
    struct bpf_program prog;
    auto filterString = Utils::toFilterString(myMac, otherIp);
    std::cout << "filter string is " << filterString << std::endl;

    if(pcap_compile(handle, &prog, filterString.c_str(), 0, *reinterpret_cast<uint32_t*>(myIp)) == -1)
        throw std::runtime_error{"Failed to compile filter"};

    if(pcap_setfilter(handle, &prog) == -1)
        throw std::runtime_error{"Failed to set filter"};
    */
    ArpPdu::request(
        handle,
        myMac,
        myIp,
        otherIp
    );

    struct pcap_pkthdr* pcapPacketHeader;
    const u_char* pcapPacket;

    pcap_next_ex(handle, &pcapPacketHeader, &pcapPacket);
    
    auto arpPacket = dynamic_cast<ArpPdu*>(Pdu::parse(pcapPacket, pcapPacketHeader->caplen));
    auto arpHeader = reinterpret_cast<ArpHeader*>(arpPacket->data());
    return MacAddr{arpHeader->sha};
}
