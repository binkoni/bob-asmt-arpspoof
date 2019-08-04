#include <iostream>
#include "Packet.h"

Packet::Packet(const unsigned char* rawPacket, uint32_t rawPacketLen)
{
    m_rawPacket = (unsigned char*)rawPacket;
    m_rawPacketLen = (uint32_t)rawPacketLen;
    std::cout << m_rawPacketLen << std::endl;
}

EthHeader* Packet::ethHeader()
{
  return reinterpret_cast<EthHeader*>(m_rawPacket);
}
IpHeader* Packet::ipHeader()
{
    return nullptr;
}
TcpHeader* Packet::tcpHeader()
{
    return nullptr;
}
ArpHeader* Packet::arpHeader()
{
    return nullptr;
}
