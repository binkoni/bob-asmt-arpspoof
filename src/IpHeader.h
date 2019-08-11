#ifndef IP_PACKET_H
#define IP_PACKET_H

#include <cstdint>
#include <sstream>
#include "EthHeader.h"

struct IpHeaderStruct
{
    unsigned char hlen:4;
    unsigned char ver:4;
    uint8_t tos;
    uint16_t tlen;
    uint16_t id;
    uint16_t flags;
    uint8_t ttl;
    uint8_t proto;
    uint16_t chksum;
    uint8_t sip[4];
    uint8_t dip[4];
} __attribute__((packed));

class IpHeader: public EthHeader
{
public:
    explicit IpHeader();
    IpHeaderStruct* headerStruct() const;
    uint8_t headerLength();
    virtual void print(std::stringstream& sstr) const override;
    virtual std::string toString() const override;
};

#endif
