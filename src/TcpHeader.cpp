#include <iostream>
#include <sstream>
#include "TcpPacket.h"
#include "IpPacket.h"

TcpPacket::TcpPacket(const unsigned char* rawPacket, uint32_t rawPacketLen):
    IpPacket{rawPacket, rawPacketLen}
{
}
/*
TcpPacket::TcpPacket():
    IpPacket{sizeof(EthHeader) + IP_PACKET_MIN_LEN}
{
    
}*/

TcpHeader* TcpPacket::tcpHeader() const
{
    const auto ipHdr = ipHeader();
    return reinterpret_cast<TcpHeader*>(reinterpret_cast<unsigned char*>(ipHdr) + ipHdr->hlen * 4);
}

void TcpPacket::print(std::stringstream& sstr) const
{
    IpPacket::print(sstr);
    sstr << TcpPacket::toString() << std::endl;
}

std::string TcpPacket::toString() const
{
    return "TcpPacket";
}
