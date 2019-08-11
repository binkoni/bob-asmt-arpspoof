#include <iostream>
#include <cstring>
#include "Packet.h"
#include "UnknownPacket.h"
#include "ArpPacket.h"
#include "TcpPacket.h"

Packet::Packet() {}

Packet::Packet(const unsigned char* rawPacket, uint32_t rawPacketLen)
{
    m_rawPacketLen = rawPacketLen;
    m_rawPacket = static_cast<unsigned char*>(malloc(m_rawPacketLen));
    std::memcpy(m_rawPacket, rawPacket, rawPacketLen);
}

Packet::Packet(uint32_t rawPacketLen)
{
    m_rawPacketLen = rawPacketLen;
    m_rawPacket = static_cast<unsigned char*>(calloc(m_rawPacketLen, sizeof(unsigned char)));
}

Packet::~Packet()
{
    delete m_rawPacket;
}

Packet* Packet::parse(const unsigned char* rawPacket, uint32_t rawPacketLen)
{
    auto header = reinterpret_cast<const EthHeader*>(rawPacket);
    switch(MY_NTOHS(header->type))
    {
        case 0x0800:
            //return new UnknownPacket{rawPacket, rawPacketLen};
            return parseIp(rawPacket, rawPacketLen);
        case 0x0806:
            return new ArpPacket{rawPacket, rawPacketLen};
        default:
            return new UnknownPacket{rawPacket, rawPacketLen};
    }
    return nullptr;
}

Packet* Packet::parseIp(const unsigned char* rawPacket, uint32_t rawPacketLen)
{
    auto header = reinterpret_cast<const IpHeader*>(IP_HDR(rawPacket));
    if(header->proto == 0x06)
    {
        return new TcpPacket{rawPacket, rawPacketLen};
    }
    return new UnknownPacket{rawPacket, rawPacketLen};
}

std::ostream& operator<<(std::ostream& ostr, const Packet& packet)
{
    ostr << std::move(packet.toString());
    return ostr;
}
