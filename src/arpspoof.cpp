#include <pcap.h>
#include <cstring>
#include <cstdio>
#include <iostream>
#include "Header.h"
#include "EthHeader.h"
#include "ArpHeader.h"
#include "IpHeader.h"
#include "TcpHeader.h"
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
    std::exit(EXIT_FAILURE);
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
        ArpHeader::reply(
            handle,
            myMac,
            senderIp,
            targetMac,
            targetIp 
        );
        ArpHeader::reply(
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
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
    if(handle == NULL)
    {
        std::cout << errbuf << std::endl;
        return -1;
    }

    EthHeader ethHeader{};
    auto ethHeaderStruct = static_cast<EthHeaderStruct*>(ethHeader.headerStruct());
    ethHeaderStruct->smac[0] = 0x00;
    ethHeaderStruct->smac[1] = 0x00;
    ethHeaderStruct->smac[2] = 0x00;
    ethHeaderStruct->smac[3] = 0x00;
    ethHeaderStruct->smac[4] = 0x00;
    ethHeaderStruct->smac[5] = 0x00;

    ethHeaderStruct->dmac[0] = 0x00;
    ethHeaderStruct->dmac[1] = 0x01;
    ethHeaderStruct->dmac[2] = 0x02;
    ethHeaderStruct->dmac[3] = 0x03;
    ethHeaderStruct->dmac[4] = 0x04;
    ethHeaderStruct->dmac[5] = 0x05;
    ethHeaderStruct->ethtype = ETHERTYPE_LOOPBACK;

    ArpHeader arpHeader{};
    auto arpHeaderStruct = static_cast<ArpHeaderStruct*>(arpHeader.headerStruct());

    Packet packet;

    packet += &ethHeader;

    packet.send(handle);
    /*
    if(pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&header), 10) == -2)
        return -1;
    if(pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&header) + 10, sizeof(EthHeaderStruct) - 10) == -2)
        return -1;
    */

}
