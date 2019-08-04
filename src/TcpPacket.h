#ifndef TCP_PACKET_H
#define TCP_PACKET_H

#include <cstdint>
#include <sstream>
#include "IpPacket.h"

struct TcpHeader {
    uint16_t sport;
    uint16_t dport;
    uint32_t seqNum;
    uint32_t ackNum;
    uint16_t hlenWithFlags;
    uint16_t wsize;
    uint16_t chksum;
    uint16_t urgPtr;
    uint8_t options[8];
} __attribute__((packed));

class TcpPacket: public IpPacket
{
public:
    TcpPacket(const unsigned char* rawPacket, uint32_t rawPacketLen);
    TcpHeader* tcpHeader() const;
    virtual void print(std::stringstream& sstr) const;
    virtual std::string toString() const;
};

#endif
