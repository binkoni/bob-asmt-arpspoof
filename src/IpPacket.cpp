#include <iostream>
#include <sstream>
#include "IpPacket.h"
#include "EthPacket.h"

IpPacket::IpPacket(const unsigned char* rawPacket, uint32_t rawPacketLen):
    EthPacket{rawPacket, rawPacketLen}
{
}

IpHeader* IpPacket::ipHeader() const
{
    return reinterpret_cast<IpHeader*>(m_rawPacket + sizeof(EthHeader));
}

void IpPacket::print(std::stringstream& sstr) const
{
    EthPacket::print(sstr);
    sstr << IpPacket::toString() << std::endl;
}

std::string IpPacket::toString() const
{
    return "IpPacket";
}


