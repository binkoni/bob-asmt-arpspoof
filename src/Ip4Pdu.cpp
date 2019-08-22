#include <arpa/inet.h>
#include "Ip4Pdu.h"
#include "Pdu.h"

Ip4Pdu::Ip4Pdu():
    Pdu{sizeof(Ip4Header)}
{}

Ip4Pdu::Ip4Pdu(const Ip4Header& header):
    Pdu{reinterpret_cast<const uint8_t*>(&header), sizeof(Ip4Header)}
{}

Ip4Pdu::Ip4Pdu(const Ip4Header* header):
    Pdu{reinterpret_cast<const uint8_t*>(header), sizeof(Ip4Header)}
{}

Ip4Pdu::Ip4Pdu(const uint8_t* header):
    Pdu{header, sizeof(Ip4Header)}
{}

uint8_t Ip4Pdu::hlen()
{
    auto header = static_cast<Ip4Header* const>(Ip4Pdu::data());
    return header->hlen;
}

uint8_t Ip4Pdu::ver()
{
    auto header = static_cast<Ip4Header* const>(Ip4Pdu::data());
    return header->ver;
}

uint8_t Ip4Pdu::tos()
{
    auto header = static_cast<Ip4Header* const>(Ip4Pdu::data());
    return header->tos;
}

uint16_t Ip4Pdu::tlen()
{
    auto header = static_cast<Ip4Header* const>(Ip4Pdu::data());
    return header->tlen;
}

uint16_t Ip4Pdu::id()
{
    auto header = static_cast<Ip4Header* const>(Ip4Pdu::data());
    return header->id;
}

uint16_t Ip4Pdu::flags()
{
    auto header = static_cast<Ip4Header* const>(Ip4Pdu::data());
    return header->flags;
}

uint8_t Ip4Pdu::ttl()
{
    auto header = static_cast<Ip4Header* const>(Ip4Pdu::data());
    return header->ttl;
}

uint8_t Ip4Pdu::proto()
{
    auto header = static_cast<Ip4Header* const>(Ip4Pdu::data());
    return header->proto;
}

uint16_t Ip4Pdu::chksum()
{
    auto header = static_cast<Ip4Header* const>(Ip4Pdu::data());
    return header->chksum;
}

Ip4Addr Ip4Pdu::sip()
{
    auto header = static_cast<Ip4Header* const>(Ip4Pdu::data());
    return header->sip;
}

Ip4Addr Ip4Pdu::dip()
{
    auto header = static_cast<Ip4Header* const>(Ip4Pdu::data());
    return header->dip;
}

void Ip4Pdu::hlen(uint8_t hlen)
{
    auto header = static_cast<Ip4Header* const>(Ip4Pdu::data());
    header->hlen = hlen;
}
void Ip4Pdu::ver(uint8_t ver)
{
    auto header = static_cast<Ip4Header* const>(Ip4Pdu::data());
    header->ver = ver;
}
void Ip4Pdu::tos(uint8_t tos)
{
    auto header = static_cast<Ip4Header* const>(Ip4Pdu::data());
    header->tos = tos;
}
void Ip4Pdu::tlen(uint16_t tlen)
{
    auto header = static_cast<Ip4Header* const>(Ip4Pdu::data());
    header->tlen = htons(tlen);
}
void Ip4Pdu::id(uint16_t id)
{
    auto header = static_cast<Ip4Header* const>(Ip4Pdu::data());
    header->id = htons(id);
}
void Ip4Pdu::flags(uint16_t flags)
{
    auto header = static_cast<Ip4Header* const>(Ip4Pdu::data());
    header->flags = htons(flags);
}

void Ip4Pdu::ttl(uint8_t ttl)
{
    auto header = static_cast<Ip4Header* const>(Ip4Pdu::data());
    header->ttl = ttl;
}
void Ip4Pdu::proto(uint8_t proto)
{
    auto header = static_cast<Ip4Header* const>(Ip4Pdu::data());
    header->proto = proto;
}
void Ip4Pdu::chksum(uint16_t chksum)
{
    auto header = static_cast<Ip4Header* const>(Ip4Pdu::data());
    header->chksum = htons(chksum);
}
void Ip4Pdu::sip(const Ip4Addr& sip)
{
    auto header = static_cast<Ip4Header* const>(Ip4Pdu::data());
    std::copy(sip.cbegin(), sip.cend(), header->sip);

}
void Ip4Pdu::dip(const Ip4Addr& dip)
{
    auto header = static_cast<Ip4Header* const>(Ip4Pdu::data());
    std::copy(dip.cbegin(), dip.cend(), header->dip);
}
/*
void Ip4Pdu::print(std::stringstream& sstr) const
{
    Ip4Pdu::print(sstr);
    sstr << Ip4Pdu::toString() << std::endl;
}
*/

std::string Ip4Pdu::toString() const
{
    return "Ip4Pdu";
}
