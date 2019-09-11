#ifndef ICMP_PDU_H
#define ICMP_PDU_H

#include <cstdint>
#include <sstream>

#include "IcmpAddr.h"
#include "Pdu.h"

struct IcmpHeader
{
    uint8_t type;
    uint8_t code;
    uint16_t chksum;
    uint32_t misc;
} __attribute__((packed));

class IcmpPdu: public Pdu
{
public:
    explicit IcmpPdu();
    explicit IcmpPdu(const IcmpHeader& header);
    explicit IcmpPdu(const IcmpHeader* header);
    explicit IcmpPdu(const uint8_t* header);

    uint8_t type() const;
    uint8_t code() const;
    uint16_t chksum() const;
    uint32_t misc() const;

    void type(uint8_t);
    void code(uint8_t);
    void chksum(uint16_t);
    void misc(uint32_t);

    virtual std::string toString() const;
};

#endif
