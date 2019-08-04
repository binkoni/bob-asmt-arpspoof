#ifndef ETH_PACKET_H
#define ETH_PACKET_H 

#include <cstdint>
#include <sstream>
#include "Packet.h"

struct EthHeader
{
    uint8_t dmac[6];
    uint8_t smac[6];
    uint16_t type;
} __attribute__((packed));

class EthPacket: public Packet
{
public:
    EthPacket(const unsigned char* rawPacket, uint32_t rawPacketLen);
    EthHeader* ethHeader() const;
    virtual void print(std::stringstream& sstr) const;
    virtual std::string toString() const;
};

#endif
