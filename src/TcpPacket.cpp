#include <iostream>
#include <cstring>
#include "TcpPacket.h"
#include "IpPacket.h"

TcpPacket::TcpPacket(const unsigned char* rawPacket, uint32_t rawPacketLen):
    IpPacket{rawPacket, rawPacketLen}
{
    std::cout << "Tcp ctor" << std::endl;
}

std::string TcpPacket::toString() const
{
    return "TcpPacket";
}
