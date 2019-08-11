#include <iostream>
#include <sstream>
#include <boost/format.hpp>
#include "UnknownPacket.h"
#include "Packet.h"

UnknownPacket::UnknownPacket(const unsigned char* rawPacket, uint32_t rawPacketLen):
    Packet{rawPacket, rawPacketLen}
{
}

void UnknownPacket::print(std::stringstream& sstr) const
{
    sstr << UnknownPacket::toString();
}

std::string UnknownPacket::toString() const
{
    return "";
}
