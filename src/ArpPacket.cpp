#include <iostream>
#include <sstream>
#include "ArpPacket.h"
#include "EthPacket.h"

ArpPacket::ArpPacket(const unsigned char* rawPacket, uint32_t rawPacketLen):
    EthPacket{rawPacket, rawPacketLen}
{
    std::cout << "ARP ctor" << std::endl;
}

ArpHeader* ArpPacket::arpHeader() const
{
    return nullptr;
}

void ArpPacket::print(std::stringstream& sstr) const
{
    EthPacket::print(sstr);
    sstr << ArpPacket::toString() << std::endl;
}

std::string ArpPacket::toString() const
{
    return "Arp Packet";
}
