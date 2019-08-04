#include <iostream>
#include "EthPacket.h"
#include "Packet.h"

EthPacket::EthPacket(const unsigned char* rawPacket, uint32_t rawPacketLen):
    Packet{rawPacket, rawPacketLen}
{
    std::cout << "Eth ctor" << std::endl;
}

std::string EthPacket::toString() const
{
    return "EthPacket";
}
