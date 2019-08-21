#ifndef IP4_PDU_H
#define IP4_PDU_H

#include <cstdint>
#include <sstream>

#include "Ip4Addr.h"
#include "Pdu.h"

struct Ip4Header
{
    uint8_t hlen:4;
    uint8_t ver:4;
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
    explicit Ip4Pdu(const Ip4Header* header);
    explicit Ip4Pdu();

    uint8_t hlen();
    uint8_t ver();
    uint8_t tos();
    uint16_t tlen();
    uint16_t id();
    uint16_t flags();
    uint8_t ttl();
    uint8_t proto();
    uint16_t chksum();
    Ip4Addr sip();
    Ip4Addr dip();

    void hlen(uint8_t);
    void ver(uint8_t);
    void tos(uint8_t);
    void tlen(uint16_t);
    void id(uint16_t);
    void flags(uint16_t);
    void ttl(uint8_t);
    void proto(uint8_t);
    void chksum(uint16_t);
    void sip(const Ip4Addr&);
    void dip(const Ip4Addr&);

    //virtual void print(std::stringstream& sstr) const override;
    virtual std::string toString() const override;
};

#endif
