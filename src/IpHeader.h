#ifndef IP_HEADER_H
#define IP_HEADER_H

#include <cstdint>
#include <sstream>
#include "Header.h"

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

class IpHeader: public Header
{
public:
    explicit IpHeader(const IpHeaderStruct* headerStruct);
    virtual void print(std::stringstream& sstr) const override;
    virtual std::string toString() const override;
};

#endif
