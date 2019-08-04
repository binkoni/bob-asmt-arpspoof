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

int main(int argc, char** argv) {
    char errbuf[PCAP_ERRBUF_SIZE];
    if(argc < 4) {
         printHelp(argv[0], errbuf);
    }

    struct ifreq myMac, myIp;
    int sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    strncpy(myMac.ifr_name, argv[1], IFNAMSIZ - 1);
    strncpy(myIp.ifr_name, argv[1], IFNAMSIZ - 1);

    if(ioctl(sock, SIOCGIFHWADDR, &myMac) != 0)
    {
        std::cout << "Failed to get MAC address" << std::endl;
        close(sock);
        std::exit(EXIT_FAILURE);
    }
    if(ioctl(sock, SIOCGIFADDR, &myIp) != 0)
    {
        std::cout << "Failed to get IP address" << std::endl;
        close(sock);
        std::exit(EXIT_FAILURE);
    }
    close(sock);

    for(int i = 0; i < 6; ++i) {
      std::printf("%02x:", (unsigned char)myMac.ifr_addr.sa_data[i]);
    }
    std::printf("\n");
    printf("%s\n", inet_ntoa(((struct sockaddr_in *)&myIp.ifr_addr)->sin_addr));


    struct sockaddr_in senderAddress;
    inet_pton(AF_INET, argv[2], &senderAddress.sin_addr);

    struct sockaddr_in targetAddress;
    inet_pton(AF_INET, argv[3], &targetAddress.sin_addr);

    auto pkt = new unsigned char[sizeof(EthHeader) + sizeof(ArpHeader)];
    auto ethHdr = reinterpret_cast<EthHeader*>(pkt);
    ethHdr->type = htons(ETHERTYPE_ARP);
    memcpy(ethHdr->smac, myMac.ifr_addr.sa_data, 6);
    for(int i = 0; i < 6; ++i)
        ethHdr->dmac[i] = 0xFF;

    auto arpHdr = reinterpret_cast<ArpHeader*>(ARP_HDR(pkt));
    arpHdr->hwtype = htons(0x0001);
    arpHdr->ptype = htons(0x0800);
    arpHdr->hwlen = 6;
    arpHdr->plen = 4;
    arpHdr->opcode = htons(0x0001);
    memcpy(arpHdr->smac, myMac.ifr_addr.sa_data, 6);
    for(int i = 0; i < 6; ++i)
        arpHdr->tmac[i] = 0x00;
    *(uint32_t*)arpHdr->sip = ((struct sockaddr_in *)&myIp.ifr_addr)->sin_addr.s_addr;
    arpHdr->tip[0] = 127;
    arpHdr->tip[1] = 0;
    arpHdr->tip[2] = 0;
    arpHdr->tip[3] = 1;
    struct pcap_pkthdr* pkt_info;
    const u_char* pktRecv;

    pcap_t* handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
    if(handle == NULL) {
        std::cout << errbuf << std::endl;
        return -1;
    }
    while(true)
    {
        pcap_sendpacket(handle, pkt, sizeof(EthHeader) + sizeof(ArpHeader));
        pcap_next_ex(handle, &pkt_info, &pktRecv);
        auto packet = Packet::parse(pktRecv, pkt_info->caplen);
        std::stringstream sstr;
        packet->print(sstr);
        std::cout << sstr.str() << std::endl;
    }
    pcap_close(handle);
}
