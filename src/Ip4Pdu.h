#ifndef IP4_PDU_H
#define IP4_PDU_H

#include <cstdint>
#include <sstream>
#include "Pdu.h"

struct Ip4Header
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

class Ip4Pdu: public Pdu
{
public:
    explicit Ip4Pdu(const Ip4Header& header);
    explicit Ip4Pdu();
    /*
    virtual void print(std::stringstream& sstr) const override;
    virtual std::string toString() const override;
    */
};

#endif
