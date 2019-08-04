#include <iostream>
#include "ArpPacket.h"
#include "EthPacket.h"

ArpPacket::ArpPacket(const unsigned char* rawPacket, uint32_t rawPacketLen):
    EthPacket{rawPacket, rawPacketLen}
{
    std::cout << "ARP ctor" << std::endl;
}

std::string ArpPacket::toString() const
{
    return "Arp Packet";
}
