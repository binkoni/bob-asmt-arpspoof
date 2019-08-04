#include <iostream>
#include <cstring>
#include "Packet.h"

Packet::Packet()
{
}

Packet::Packet(const unsigned char* rawPacket, uint32_t rawPacketLen):
    m_rawPacketLen{rawPacketLen},
    m_rawPacket{new unsigned char[rawPacketLen]}
{
    std::memcpy(m_rawPacket, rawPacket, rawPacketLen);
    std::cout << "Packet ctor" << std::endl;
}

Packet::~Packet()
{
    delete m_rawPacket;
}

Packet* Packet::parse(const unsigned char* rawPacket, uint32_t rawPacketLen)
{
    auto header = reinterpret_cast<const EthHeader*>(rawPacket);
    std::cout << std::hex << MY_NTOHS(header->type) << std::dec << std::endl;;
    switch(MY_NTOHS(header->type))
    {
        case 0x0800:
            std::cout << "IP" << std::endl;
            return parseIp(rawPacket, rawPacketLen);
        case 0x0806:
            return new ArpPacket{rawPacket, rawPacketLen};
    }
    return nullptr;
}

Packet* Packet::parseIp(const unsigned char* rawPacket, uint32_t rawPacketLen)
{
    auto header = reinterpret_cast<const IpHeader*>(rawPacket);
    if(header->proto == 0x06)
    {
        return new TcpPacket{rawPacket, rawPacketLen};
    }
    return nullptr;
}

std::ostream& operator<<(std::ostream& ostr, const Packet& packet)
{
    ostr << std::move(packet.toString());
    return ostr;
}
