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
private:
    std::vector<uint8_t> m_options;
public:
    explicit Ip4Pdu();
    explicit Ip4Pdu(const Ip4Header& header);
    explicit Ip4Pdu(const Ip4Header* header);
    explicit Ip4Pdu(const uint8_t* header);

    constexpr uint8_t defaultSize() const;
    uint8_t hlen() const;
    uint8_t ver() const;
    uint8_t tos() const;
    uint16_t tlen() const;
    uint16_t id() const;
    uint16_t flags() const;
    uint8_t ttl() const;
    uint8_t proto() const;
    uint16_t chksum() const;
    Ip4Addr sip() const;
    Ip4Addr dip() const;

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
    virtual std::string toString() const;

};

#endif
