#include <iostream>
#include <cstring>
#include "IpPacket.h"
#include "EthPacket.h"

IpPacket::IpPacket(const unsigned char* rawPacket, uint32_t rawPacketLen):
    EthPacket{rawPacket, rawPacketLen}
{
    std::cout << "Ip ctor" << std::endl;
}

std::string IpPacket::toString() const
{
    return "IpPacket";
}


