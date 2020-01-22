#include <arpa/inet.h>
#include <boost/format.hpp>
#include "Ip4Pdu.h"
#include "Pdu.h"

Ip4Pdu::Ip4Pdu(size_t hlen)
{
    Pdu::parse(sizeof(Ip4Header));
    m_options.reserve(hlen * 4 - sizeof(Ip4Header));
    Ip4Pdu::hlen(hlen);
}

Ip4Pdu::Ip4Pdu(const uint8_t* header)
{
    Pdu::parse(header, sizeof(Ip4Header));
    const auto hlen = Ip4Pdu::hlen();
    m_options.reserve(hlen * 4);
    std::copy_n(header + sizeof(Ip4Header), hlen * 4, m_options.begin());
}

Ip4Pdu::Ip4Pdu(const Ip4Header& header):
Ip4Pdu::Ip4Pdu(reinterpret_cast<const uint8_t*>(&header))
{}

Ip4Pdu::Ip4Pdu(const Ip4Header* header):
Ip4Pdu::Ip4Pdu(reinterpret_cast<const uint8_t*>(header))
{}

constexpr uint8_t Ip4Pdu::defaultSize() const
{
    return 20;
}

uint8_t Ip4Pdu::hlen() const
{
    auto header = static_cast<Ip4Header* const>(Ip4Pdu::data());
    return header->hlen;
}

uint8_t Ip4Pdu::ver() const
{
    auto header = static_cast<Ip4Header* const>(Ip4Pdu::data());
    return header->ver;
}

uint8_t Ip4Pdu::tos() const
{
    auto header = static_cast<Ip4Header* const>(Ip4Pdu::data());
    return header->tos;
}

uint16_t Ip4Pdu::tlen() const
{
    auto header = static_cast<Ip4Header* const>(Ip4Pdu::data());
    return ntohs(header->tlen);
}

uint16_t Ip4Pdu::id() const
{
    auto header = static_cast<Ip4Header* const>(Ip4Pdu::data());
    return ntohs(header->id);
}

uint16_t Ip4Pdu::flags() const
{
    auto header = static_cast<Ip4Header* const>(Ip4Pdu::data());
    return ntohs(header->flags);
}

uint8_t Ip4Pdu::ttl() const
{
    auto header = static_cast<Ip4Header* const>(Ip4Pdu::data());
    return header->ttl;
}

uint8_t Ip4Pdu::proto() const
{
    auto header = static_cast<Ip4Header* const>(Ip4Pdu::data());
    return header->proto;
}

uint16_t Ip4Pdu::chksum() const
{
    auto header = static_cast<Ip4Header* const>(Ip4Pdu::data());
    return ntohs(header->chksum);
}

Ip4Addr Ip4Pdu::sip() const
{
    auto header = static_cast<Ip4Header* const>(Ip4Pdu::data());
    return header->sip;
}

Ip4Addr Ip4Pdu::dip() const
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
    std::stringstream sstr;
    sstr << boost::format("ipv4 hlen %u\n") % int(Ip4Pdu::hlen());
    sstr << boost::format("ipv4 ver %u\n") % int(Ip4Pdu::ver());
    sstr << boost::format("ipv4 tos %u\n") % int(Ip4Pdu::tos());
    sstr << boost::format("ipv4 tlen %u\n") % Ip4Pdu::tlen();
    sstr << boost::format("ipv4 id %u\n") % Ip4Pdu::id();
    sstr << boost::format("ipv4 flags %u\n") % Ip4Pdu::flags();
    sstr << boost::format("ipv4 ttl %u\n") % int(Ip4Pdu::ttl());
    sstr << boost::format("ipv4 proto %X\n") % int(Ip4Pdu::proto());
    sstr << boost::format("ipv4 chksum %X\n") % Ip4Pdu::chksum();
    sstr << boost::format("ipv4 sip %s\n") % Ip4Pdu::sip().toString();
    sstr << boost::format("ipv4 dip %s\n") % Ip4Pdu::dip().toString();

    return sstr.str();
}
