#ifndef ARP_PACKET_H
#define ARP_PACKET_H

#include <cstdint>
#include <sstream>
#include "EthPacket.h"

struct ArpHeader {
    uint16_t hwtype;
    uint16_t ptype;
    uint8_t hwlen;
    uint8_t plen;
    uint16_t opcode;
    uint8_t smac[6];
    uint8_t sip[4];
    uint8_t tmac[6];
    uint8_t tip[4];
} __attribute__((packed));

class ArpPacket: public EthPacket
{
public:
    ArpPacket(const unsigned char* rawPacket, uint32_t rawPacketLen);
    ArpHeader* arpHeader() const;
    virtual void print(std::stringstream& sstr) const;
    virtual std::string toString() const;
};

#endif
