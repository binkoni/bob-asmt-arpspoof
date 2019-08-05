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
#include "Helper.h"
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

std::string toFilterString(uint8_t mac[6], uint32_t ipInt)
{
    return boost::str(boost::format("(arp[6:2] = 2) and src host %s and ether dst %s") % Helper::toIpString(ipInt) % Helper::toMacString(mac));
}

void requestArp(pcap_t* handle, uint8_t senderMac[6], uint8_t senderIp[4], uint8_t targetIp[4])
{
    auto pkt = new unsigned char[sizeof(EthHeader) + sizeof(ArpHeader)];
    auto ethHdr = reinterpret_cast<EthHeader*>(pkt);
    auto arpHdr = reinterpret_cast<ArpHeader*>(ARP_HDR(pkt));

    ethHdr->type = htons(ETHERTYPE_ARP);
    memcpy(ethHdr->smac, senderMac, 6);
    memset(ethHdr->dmac, 0xFF, 6);

    arpHdr->hwtype = htons(0x0001);
    arpHdr->ptype = htons(ETHERTYPE_IP);
    arpHdr->hwlen = 6;
    arpHdr->plen = 4;
    arpHdr->opcode = htons(ARPOP_REQUEST);

    memcpy(arpHdr->smac, senderMac, 6);
    memcpy(arpHdr->sip, senderIp, 4);


    memset(arpHdr->tmac, 0, 6);
    memcpy(arpHdr->tip, targetIp, 4);


    if(pcap_sendpacket(handle, pkt, sizeof(EthHeader) + sizeof(ArpHeader)) == -1)
    {
        std::cout << "pcap_sendpacket failed!" << std::endl;
    }
    //delete pkt;
}

/*
void replyArp(pcap_t* handle, from, to)
{
    auto pkt = new unsigned char[sizeof(EthHeader) + sizeof(ArpHeader)];
    auto ethHdr = reinterpret_cast<EthHeader*>(pkt);
    auto arpHdr = reinterpret_cast<ArpHeader*>(ARP_HDR(pkt));
}
*/

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

    auto myIp = ((struct sockaddr_in *)&myIpIfr.ifr_addr)->sin_addr;
    auto myMac = myMacIfr.ifr_addr.sa_data;

    for(int i = 0; i < 6; ++i)
    {
      std::printf("%02x:", (unsigned char)myMac[i]);
    }
    std::printf("\n");
    printf("%s\n", inet_ntoa(myIp));

    struct sockaddr_in senderAddress;
    inet_pton(AF_INET, argv[2], &senderAddress.sin_addr);

    struct sockaddr_in targetAddress;
    inet_pton(AF_INET, argv[3], &targetAddress.sin_addr);

    /*
    auto pkt = new unsigned char[sizeof(EthHeader) + sizeof(ArpHeader)];
    auto ethHdr = reinterpret_cast<EthHeader*>(pkt);
    ethHdr->type = htons(ETHERTYPE_ARP);
    memcpy(ethHdr->smac, myMacIfr.ifr_addr.sa_data, 6);
    for(int i = 0; i < 6; ++i)
        ethHdr->dmac[i] = 0xFF;

    auto arpHdr = reinterpret_cast<ArpHeader*>(ARP_HDR(pkt));
    arpHdr->hwtype = htons(0x0001);
    arpHdr->ptype = htons(0x0800);
    arpHdr->hwlen = 6;
    arpHdr->plen = 4;
    arpHdr->opcode = htons(ARPOP_REQUEST);
    memcpy(arpHdr->smac, myMacIfr.ifr_addr.sa_data, 6);
    for(int i = 0; i < 6; ++i)
        arpHdr->tmac[i] = 0x00;
    *(uint32_t*)arpHdr->sip = myIp.s_addr;

    arpHdr->tip[0] = 127;
    arpHdr->tip[1] = 0;
    arpHdr->tip[2] = 0;
    arpHdr->tip[3] = 1;
    */
    struct pcap_pkthdr* pkt_info;
    const u_char* pktRecv;

    pcap_t* handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
    if(handle == NULL)
    {
        std::cout << errbuf << std::endl;
        return -1;
    }
    for(int i = 0; i < 100; ++i) {
    requestArp(
        handle,
        reinterpret_cast<uint8_t*>(myMac),
        reinterpret_cast<uint8_t*>(&myIp.s_addr),
        reinterpret_cast<uint8_t*>(&senderAddress.sin_addr.s_addr));
    }

    /*
    struct bpf_program prog;

    auto filterString = toFilterString(reinterpret_cast<uint8_t*>(myMac), myIp.s_addr);
    std::cout << "Filterstring: " << filterString.c_str() << ")" << std::endl;
    if(pcap_compile(handle, &prog, filterString.c_str(), 0, myIp.s_addr) == -1)
    {
        std::cout << "Failed to compile filter" << std::endl;
        std::exit(EXIT_FAILURE);
    }
    if(pcap_setfilter(handle, &prog) == -1)
    {
        std::cout << "Failed to set filter" << std::endl;
        std::exit(EXIT_FAILURE);
    }
    std::cout << Helper::toIpString(myIp.s_addr) << std::endl;

    while(true)
    {
        //pcap_sendpacket(handle, pkt, sizeof(EthHeader) + sizeof(ArpHeader));
        pcap_next_ex(handle, &pkt_info, &pktRecv);
        auto packet = Packet::parse(pktRecv, pkt_info->caplen);
        std::stringstream sstr;
        packet->print(sstr);
        std::cout << sstr.str() << std::endl;
    }
    */
    pcap_close(handle);
}
