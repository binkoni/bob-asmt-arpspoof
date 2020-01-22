#include <pcap.h>
#include <cstring>
#include <cstdio>
#include <iostream>
#include "Pdu.h"
#include "EthPdu.h"
#include "ArpPdu.h"
#include "Ip4Pdu.h"
#include "TcpPdu.h"
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
#include "Packet.h"
#include <boost/format.hpp>

void printHelp(const char* argv0)
{
    char errbuf[PCAP_ERRBUF_SIZE];

    std::cout << "send_arp" << std::endl;
    std::cout << "Usage: " << argv0 << " <interface> <sender ip> <target ip>" << std::endl;
    std::cout << "Available Devices" << std::endl;
    pcap_if_t* alldevsp;
    pcap_findalldevs(&alldevsp, errbuf);
    if(alldevsp != NULL) {
      for(pcap_if_t* curdevp = alldevsp; curdevp->next != NULL; curdevp = curdevp->next)
        std::cout << "  " << curdevp->name << std::endl;
    }
}

/*
int main(int argc, char** argv) {
    char errbuf[PCAP_ERRBUF_SIZE];
    if(argc < 4) {
         printHelp(argv[0]);
         return EXIT_FAILURE;
    }

    auto iface = argv[1];

    uint8_t senderIp[4];
    Utils::fromIpString(argv[2], senderIp);
    uint8_t targetIp[4];
    Utils::fromIpString(argv[3], targetIp);

    uint8_t myMac[6];
    Utils::getMyMac(iface, myMac);
    uint8_t myIp[4];
    Utils::getMyIp(iface, myIp);

    for(int i = 0; i < 6; ++i)
    {
      std::printf("%02x:", (unsigned char)myMac[i]);
    }
    std::printf("\n");
    //printf("%s\n", inet_ntoa(myIp));

    std::cout << "sender: " << argv[2] << std::endl;
    std::cout << "target: " << argv[3] << std::endl;


    pcap_t* handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
    if(handle == NULL)
    {
        std::cout << errbuf << std::endl;
        return -1;
    }
    uint8_t senderMac[6];
    uint8_t targetMac[6];

    Utils::queryMac(handle, myMac, myIp, senderIp, senderMac);
    Utils::queryMac(handle, myMac, myIp, targetIp, targetMac);
    
    while(true) {
        ArpPdu::reply(
            handle,
            myMac,
            senderIp,
            targetMac,
            targetIp 
        );
        ArpPdu::reply(
            handle,
            myMac,
            targetIp,
            senderMac,
            senderIp
        );
    }
    pcap_close(handle);
}
*/

int main(int argc, char* argv[])
{

    if(argc < 4 || argc % 2 != 0)
    {
        printHelp(argv[0]);
        std::exit(EXIT_FAILURE);
    }

    for(int i = 2; i < argc - 1; i += 2)
    {
        printf("%s\n", argv[i]);
        printf("%s\n", argv[i + 1]);
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
    if(handle == NULL)
    {
        std::cout << errbuf << std::endl;
        return -1;
    }
    struct pcap_pkthdr* pkt_header;
    const u_char* pkt_data;
    pcap_next_ex(handle, &pkt_header, &pkt_data);

    while(true)
    {
        auto packet = Packet::parse(pkt_data, pkt_header->caplen);
        for(auto it = packet.crbegin(); it != packet.crend(); ++it)
            std::cout << (*it)->toString() << std::endl;
        std::cout << std::string(10, '-') << std::endl;
    }

    Packet packet;

    EthHeader ethHeader;
    ethHeader.smac[0] = 0x00;
    ethHeader.smac[1] = 0x00;
    ethHeader.smac[2] = 0x00;
    ethHeader.smac[3] = 0x00;
    ethHeader.smac[4] = 0x00;
    ethHeader.smac[5] = 0x00;

    ethHeader.dmac[0] = 0x00;
    ethHeader.dmac[1] = 0x01;
    ethHeader.dmac[2] = 0x02;
    ethHeader.dmac[3] = 0x03;
    ethHeader.dmac[4] = 0x04;
    ethHeader.dmac[5] = 0x05;
    ethHeader.ethtype = ETHERTYPE_LOOPBACK;

    packet << std::make_unique<EthPdu>(&ethHeader);

    ArpHeader arpHeader;
    ArpPdu arpPdu{&arpHeader};


/*
    packet.send(handle);
    if(pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&header), 10) == -2)
        return -1;
    if(pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&header) + 10, sizeof(EthHeader) - 10) == -2)
        return -1;
*/
    std::cout << Utils::getMyIp("wlp1s0").toString() << std::endl;
    std::cout << Utils::getMyMac("wlp1s0").toString() << std::endl;
}
