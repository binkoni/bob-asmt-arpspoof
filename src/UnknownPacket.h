#ifndef UNKNOWN_PACKET_H
#define UNKNOWN_PACKET_H

#include <cstdint>
#include <sstream>
#include "Packet.h"

class UnknownPacket: public Packet
{
public:
    UnknownPacket(const unsigned char* rawPacket, uint32_t rawPacketLen);
    virtual void print(std::stringstream& sstr) const;
    virtual std::string toString() const;
};

#endif
